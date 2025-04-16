import os
import logging
import docker
from docker.tls import TLSConfig
from urllib.parse import urlparse
import threading
import traceback
import requests
import signal
import sys
import time
import random
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from notifier import send_notification
from line_processor import LogProcessor
from load_config import load_config, format_pydantic_error
from pydantic import ValidationError


logging.basicConfig(
    level="INFO",
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", mode="w"),
        logging.StreamHandler()
    ]
)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)    
logging.getLogger("docker").setLevel(logging.INFO)
logging.getLogger("watchdog").setLevel(logging.WARNING)


class DockerLogMonitor:
    """
    In this class a thread is started for every container that is running and set in the config 
    One thread is started to monitor docker events to watch for new containers and containers that are being stopped to stop their monitoring.

    There are a few collections that are referenced between functions I want to document here:

        - self.line_processor_instances: Dict keyed by container.name, each containing a dict with {'container_stop_event': threading event, 'processor' processor instance}
            - processor is the instance of the LogProcessor class and is used to process the log lines for one container.
                It is stored to be able to reload the config variables (keywords, settings, etc) when changed. 
                When a container is stopped and started again the old processor instance is re-used.
            - container_stop_event is a threading event used to stop all threads that are running to monitor one container including the flush thread in the processor instance
        
        - self.stream_connections: Dict of log stream connections keyed by container.name (used to close the log stream, effectively stopping the log_monitor thread that is monitoring that container and thus the flush thread)
        
        - self.monitored_containers: Dict of Docker Container objects that are currently being monitored keyed by container.id
        
        - self.selected_containers: List of container names that are set in the config

        - self.threads: List of threads that are started to monitor container logs and docker events

    """
    def __init__(self, client, config, hostname):
        self.hostname = hostname  # empty string if only one client is being monitored, otherwise the hostname of the client 
        self.config = config
        
        self.logger = logging.getLogger(f"Monitor-{self.hostname}")
        self.logger.handlers.clear()
        handler = logging.StreamHandler()
        formatter = (logging.Formatter(f'%(asctime)s - %(levelname)s - [Host: {self.hostname}] - %(message)s') 
                     if self.hostname else logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        self.logger.propagate = False

        self.client = client
        self.selected_containers = [c for c in self.config.containers]
        self.shutdown_event = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.line_processor_instances = {}
        self.processors_lock = threading.Lock()

        self.stream_connections = {}
        self.stream_connections_lock = threading.Lock()
        self.monitored_containers = {}


    def reload_config(self, config):
        self.config = config
        self.logger.setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        self.selected_containers = [c for c in self.config.containers]
        try:
            # stop monitoring containers that are no longer in the config
            stop_monitoring = [c for _, c in self.monitored_containers.items() if c.name not in self.selected_containers]
            for c in stop_monitoring:
                container_stop_event = self.line_processor_instances[c.name]["container_stop_event"]
                container_stop_event.set()
                self.close_stream_connecion(c.name)
                self.monitored_containers.pop(c.id)
            # reload config variables in the line processor instances to update keywords and other settings
            for container in self.line_processor_instances.keys():
                processor = self.line_processor_instances[container]["processor"]
                processor.load_config_variables(self.config)
            # start monitoring new containers that are in the config but not monitored yet
            containers_to_monitor = [c for c in self.client.containers.list() if c.name in self.selected_containers and c.id not in self.monitored_containers.keys()]
            for c in containers_to_monitor:
                self.logger.info(f"New Container to monitor: {c.name}")
                if self.line_processor_instances.get(c.name) is not None:
                    container_stop_event = self.line_processor_instances[c.name]["container_stop_event"]
                    container_stop_event.clear()
                self.monitor_container(c)
                self.monitored_containers[c.id] = c

            self.start_message()
            if not self.config.settings.reload_config:
                self.observer.stop()
                self.logger.info("Config watcher stopped because reload_config is set to False.")
            
        except Exception as e:
            self.logger.error(f"Error handling config changes: {e}")


    def add_thread(self, thread):
        with self.threads_lock:
            self.threads.append(thread)

    def add_processor_instance(self, processor, container_stop_event, container_name):
        with self.processors_lock:
            if container_name not in self.line_processor_instances:
                self.line_processor_instances[container_name] = {"processor": processor, "container_stop_event": container_stop_event}
                return True
            else:
                return False

    def add_stream_connection(self, container_name, connection):
        with self.stream_connections_lock:
            self.stream_connections[container_name] = connection


    def close_stream_connecion(self, container_name):
        stream = self.stream_connections.get(container_name)
        if stream:
            try: 
                stream.close()
                self.stream_connections.pop(container_name)
            except Exception as e:
                self.logger.warning(f"Error trying do close stream during cleanup: {e}")
        else:
            self.logger.debug(f"Could not find log stream connection for container {container_name}")


    def handle_error(self, error_count, last_error_time):
            new_count = error_count + 1
            current_time = time.time()
            if current_time - last_error_time > 180:
                new_count = 1
            return new_count, current_time
    

    def monitor_container(self, container):    
        def check_container(container_start_time):
            try:
                container.reload()
                if container.status != "running":
                    return False
                if container.attrs['State']['StartedAt'] != container_start_time:
                    return False
            except docker.errors.NotFound:
                self.logger.error(f"Container {container.name} not found during container check. Stopping monitoring.")
                return False
            except requests.exceptions.ConnectionError as ce: 
                self.logger.error(f"Can not connect to Container {container.name} {ce}")
            except Exception as e:
                self.logger.error(f"Error while checking container {container.name}: {e}")
                #self.logger.debug(traceback.format_exc())
            return True

        def log_monitor():
            """
            I am using a buffer in case the logstream has an unfinished log line that can't be decoded correctly.
            """
            container_start_time = container.attrs['State']['StartedAt']
            self.logger.info(f"Monitoring for Container started: {container.name}")
            error_count = 0
            last_error_time = time.time()  

            # re-use old line processor instance if it exists, otherwise create a new one
            if container.name in self.line_processor_instances:
                self.logger.debug(f"{container.name}: Re-Using old line processor")    
                processor, container_stop_event = self.line_processor_instances[container.name]["processor"], self.line_processor_instances[container.name]["container_stop_event"]
                processor._start_flush_thread()
            else:
                container_stop_event = threading.Event()
                processor = LogProcessor(self.logger, self.hostname, self.config, container, container_stop_event)
                self.add_processor_instance(processor, container_stop_event, container.name)

            container_stop_event.clear()
            while not self.shutdown_event.is_set() and not container_stop_event.is_set():
                buffer = b""
                try:
                    now = datetime.now()
                    log_stream = container.logs(stream=True, follow=True, since=now)
                    self.add_stream_connection(container.name, log_stream)
                    self.logger.info(f"{container.name}: Log Stream started")
                    for chunk in log_stream:
                        MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB
                        buffer += chunk
                        if len(buffer) > MAX_BUFFER_SIZE:
                            self.logger.error(f"{container.name}: Buffer overflow detected for container, resetting")
                            buffer = b""
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                log_line_decoded = str(line.decode("utf-8")).strip()
                            except UnicodeDecodeError:
                                log_line_decoded = line.decode("utf-8", errors="replace").strip()
                                self.logger.warning(f"{container.name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                            if log_line_decoded: 
                                processor.process_line(log_line_decoded)
                        if self.shutdown_event.is_set():
                            break
                    if not check_container(container_start_time):
                        break

                except docker.errors.NotFound as e:
                    self.logger.error(f"Container {container} during Log Stream: {e}")
                    error_count, last_error_time = self.handle_error(error_count, last_error_time) 
                    time.sleep(random.uniform(0.1, 0.8)) # to prevent all threads trying to reconnect at the same time when there are connection problems (especially with a proxy)
                except docker.errors.APIError as e:
                    error_count, last_error_time = self.handle_error(error_count, last_error_time)
                    time.sleep(random.uniform(0.1, 0.8))
                except Exception as e:
                    self.logger.error("Error trying to monitor %s: %s", container.name, e)
                    self.logger.error("Error details: %s", str(e.__class__.__name__))
                    #self.logger.debug(traceback.format_exc())
                    error_count, last_error_time = self.handle_error(error_count, last_error_time)
                    time.sleep(random.uniform(0.1, 0.8))
                finally:
                    if self.shutdown_event.is_set() or container_stop_event.is_set():   
                        try:
                            self.logger.debug(f"{container.name}: Closing log stream. Shutdown event or restart event is set.")
                            log_stream.close()  
                        except Exception as e:
                            self.logger.debug(f"{container.name}: Error closing stream: Container {str(e)}")
                        finally:
                            break
                    if not check_container(container_start_time):
                        self.logger.debug(f"{container.name} is not running or was restarted. Getting rid of old thread")
                        try:
                            log_stream.close()
                        except Exception as e:
                            self.logger.error(f"Could not close Log Stream for container {container.name}")
                        finally:
                            break
                    # if there are more than 5 errors in one minute the while loop stops
                    if time.time() - last_error_time > 60:
                        error_count = 0
                    if error_count > 10:
                        self.logger.error(f"Error trying to establish Log Stream for {container.name}. Critical error threshold (10) reached.")
                        log_stream.close()  
                        container_stop_event.set() # to stop flush threads in the line processor instances
                        break
                    self.logger.info(f"{container.name}: Log Stream stopped. Reconnecting...")
            self.logger.info(f"{container.name}: Monitoring stopped for container.")
            container_stop_event.set()

        thread = threading.Thread(target=log_monitor, daemon=True)
        self.add_thread(thread)
        thread.start()

    # This function is called from outside this class to start the monitoring of one host and its containers
    def start(self):
        running_containers = self.client.containers.list()
        containers_to_monitor = [c for c in running_containers if c.name in self.selected_containers]
        for container in containers_to_monitor:
            self.monitor_container(container)
            self.monitored_containers[container.id] = container
        self.watch_events()
        self.start_message()


    def start_message(self):
        monitored_containers_message = "\n - ".join(c.name for id, c in self.monitored_containers.items())
        unmonitored_containers = [c for c in self.selected_containers if c not in [c.name for id, c in self.monitored_containers.items()]]
        unmonitored_containers_message = "\n - ".join(unmonitored_containers) if unmonitored_containers else ""
        self.logger.info(f"These containers are being monitored:\n - {monitored_containers_message}")
        if unmonitored_containers:
            unmonitored_containers_str = "\n - ".join(unmonitored_containers)
            self.logger.info(f"These selected Containers are not running:\n - {unmonitored_containers_str}")
        else:
            unmonitored_containers_str = ""

        if self.config.settings.disable_start_message is False:
            send_notification(self.config, "loggifly", "LoggiFly", 
                              f"""The program is running and monitoring these selected Containers:\n - {monitored_containers_message}
                              \nThese selected Containers are not running:\n - {unmonitored_containers_message}""", hostname=self.hostname
                              )


    def watch_events(self):
        """
        When a new selected container is started the monitor_container function is called to start monitoring it.
        When a selected container is stopped the stream connection is closed (causing the threads associated with it to stop) 
        and the container is removed from the monitored containers.
        """
        def event_handler():
            error_count = 0
            last_error_time = time.time()
            while not self.shutdown_event.is_set():
                self.logger.info("Event Handler started. Watching for new containers...")
                now = time.time()
                try: 
                    for event in self.client.events(decode=True, filters={"event": ["start", "stop"]}, since=now):
                        if self.shutdown_event.is_set():
                            self.logger.debug("Shutdown event is set. Stopping event handler.")
                            break
                        container = self.client.containers.get(event["Actor"]["ID"])
                        if event.get("Action") == "start":
                            if container.name in self.selected_containers:
                                self.logger.info(f"Monitoring new container: {container.name}")
                                send_notification(self.config, "Loggifly", "LoggiFly", f"Monitoring new container: {container.name}", hostname=self.hostname)
                                self.monitor_container(container)
                                self.monitored_containers[container.id] = container
                        elif event.get("Action") == "stop":
                            if container.id in self.monitored_containers:
                                self.logger.info(f"The Container {container.name} was stopped")
                                self.monitored_containers.pop(container.id)
                                container_stop_event = self.line_processor_instances[container.name]["container_stop_event"]
                                container_stop_event.set()
                                self.close_stream_connecion(container.name)

                except docker.errors.NotFound as e:
                    self.logger.error(F"Event-Handler: Container {container} not found: {e}")
                except Exception as e:  
                    if self.shutdown_event.is_set():
                        break
                    self.logger.error(f"Event-Handler was stopped {e}. Trying to restart it.")
                    error_count, last_error_time = self.handle_error(error_count, last_error_time)
                    time.sleep(0.3)
                finally:
                    if self.shutdown_event.is_set():
                        self.logger.debug("Event handler is shutting down.")
                        break
                    if time.time() - last_error_time > 60:
                        error_count = 0
                    if error_count > 10:
                        self.logger.error(f"Error trying to read docker events. Critical error threshold (10) reached.")
                        break
                    self.logger.debug(f"Restarting Event Handler")
            self.logger.debug("Event handler stopped.")

        thread = threading.Thread(target=event_handler, daemon=True)
        self.add_thread(thread)
        thread.start()
    

    def cleanup(self):    
        """
        This function is called when the program is shutting down. 
        By closing the stream connections the log stream which is blocked until the next log line gets released allowing the threads to fninish.
        The only thread that can not easily be stopped is the event_handler, because it is is blocked.
        """  
        with self.stream_connections_lock:
            for container, _ in self.stream_connections.copy().items():
                self.close_stream_connecion(container)
            self.logger.debug(f"No Log Stream Connections left" if len(self.stream_connections) ==0 else f"{len(self.stream_connections)} Log Stream Connections remaining")

        with self.threads_lock:
            alive_threads = []
            for thread in self.threads[::-1]:
                if thread is not threading.current_thread() and thread.is_alive():
                    thread.join(timeout=1.5)
                    if thread.is_alive():
                        self.logger.debug(f"Thread {thread.name} could not be stopped")
                        alive_threads.append(thread)
            self.threads = alive_threads
        try:
            self.client.close()
            self.logger.info("Shutdown completed")
        except Exception as e:
            self.logger.warning(f"Error while trying do close docker client connection during cleanup: {e}")
        # self.logger.debug(f"Threads still alive {len(alive_threads)}: {alive_threads}")
        # self.logger.debug(f"Threading Enumerate: {threading.enumerate()}")


def create_handle_signal(monitor_instances, config, config_observer):
    def handle_signal(signum, frame):
        if not config.settings.disable_shutdown_message:
            send_notification(config, "LoggiFly", "LoggiFly", "Shutting down")
        for monitor in monitor_instances.values():
            monitor.shutdown_event.set()
            threading.Thread(target=monitor.cleanup).start()
        config_observer.stop()
        config_observer.join()

    return handle_signal
    
class ConfigHandler(FileSystemEventHandler):
    """
    When a config.yaml change is detected, the reload_config method is called on each host's DockerLogMonitor instance.
    This method then updates all LogProcessor instances (from line_processor.py) by calling their load_config_variables function.
    This ensures that any new keywords, settings, or other configuration changes are correctly applied especiaööy in the code that handles keyword searching in line_processor.py.    
    """
    def __init__(self, monitor_instances, config):
        self.monitor_instances = monitor_instances  
        self.last_config_reload_time = 0
        self.config = config

    def on_modified(self, event):
        if self.config.settings.reload_config and not event.is_directory and event.src_path.endswith('config.yaml'):
            if time.time() - self.last_config_reload_time < 3:
                logging.info("Config reload skipped, waiting for 3 seconds")
                return
            logging.info("Config change detected, reloading config...")
            if not self.config.settings.disable_config_reload_message:
                send_notification(self.config, "Loggifly", "LoggiFly", "Reloading Config...")
            time.sleep(0.3)  
            try:
                self.config = load_config()
            except ValidationError as e:
                self.logger.critical(f"Error reloading Config (using old config) {format_pydantic_error(e)}")

            for monitor in self.monitor_instances.values():
                monitor.reload_config(self.config)
            self.last_config_reload_time = time.time()  


def start_config_watcher(monitor_instances, config):
    observer = Observer()
    observer.schedule(ConfigHandler(monitor_instances, config), path="/app/config.yaml", recursive=False)
    observer.start()
    return observer
    

def create_docker_clients():
    """
    This function creates Docker clients for all hosts specified in the DOCKER_HOST environment variables + the mounted docker socket.
    When the port 2376 is used TLS certificates are searched in '/certs/{host}' (to use in case of multiple hosts) and '/certs' 
    with host being the IP or FQDN of the host.
    """
    def get_tls_config(hostname):
        cert_locations = [
            (os.path.join("/certs", hostname)),   
            (os.path.join("/certs"))             
        ]

        for cert_dir in cert_locations:
            logging.debug(f"Checking TLS certs for {hostname} in {cert_dir}")
            ca = os.path.join(cert_dir, "ca.pem")
            cert = os.path.join(cert_dir, "cert.pem")
            key = os.path.join(cert_dir, "key.pem")
            
            if all(os.path.exists(f) for f in [ca, cert, key]):
                logging.debug(f"Found TLS certs for {hostname} in {cert_dir}")
                return TLSConfig(client_cert=(cert, key), ca_cert=ca, verify=True)
        return None

    docker_host = os.environ.get("DOCKER_HOST", "")
    hosts = [h.strip() for h in docker_host.split(",") if h.strip()]
    if os.path.exists("/var/run/docker.sock"):
        hosts.append("unix:///var/run/docker.sock")
    clients = []

    for host in hosts:
        logging.debug(f"Creating Docker Client for {host}")
        parsed = urlparse(host)
        tls_config = None
        if parsed.scheme == "unix":
            pass
        elif parsed.scheme == "tcp":
            if parsed.port == 2375:
                pass
            elif parsed.port == 2376:
                hostname = parsed.hostname
                tls_config = get_tls_config(hostname)

        try:
            clients.append((docker.DockerClient(base_url=host, tls=tls_config), host))
        except docker.errors.DockerException as e:
            logging.error(f"Error creating Docker client for {host}: {e}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error creating Docker client for {host}: {e}")
            continue

    logging.info(f"Connections to Docker-Clients established for {', '.join([client[1] for client in clients])}"
                 if len(clients) > 1 else "Connected to Docker Client")
    return clients


def start_loggifly():
    try:
        config = load_config()
    except ValidationError as e:
        logging.critical(f"Error loading Config: {format_pydantic_error(e)}")
        logging.info("Waiting 10s to prevent restart loop...")
        time.sleep(15)
        sys.exit(1)

    logging.getLogger().setLevel(getattr(logging, config.settings.log_level.upper(), logging.INFO))
    logging.info(f"Log-Level set to {config.settings.log_level}")

    clients = create_docker_clients()
    monitor_instances = {}
    hostname = ""
    for number, (client, host) in enumerate(clients, start=1):
        if len(clients) > 1:
            try:
                hostname = client.info()["Name"]
            except Exception as e:
                hostname = f"Host-{number}"
                logging.warning(f"Could not get hostname for {host}. LoggiFly will call this host '{hostname}' in notifications and in logging to differentiate it from the other hosts. "
                                "\nThis error might have been raised because you are using a Socket Proxy without the environment variable 'INFO=1'"
                                f"\nError details: {e}")
        logging.info(f"Starting monitoring for {host} {'(' + hostname + ')' if hostname else ''}")
        monitor = DockerLogMonitor(client, config, hostname)
        monitor_instances[host] = monitor
        monitor.start()      
        
    config_observer = start_config_watcher(monitor_instances, config)
    signal.signal(signal.SIGTERM, create_handle_signal(monitor_instances, config, config_observer))
    signal.signal(signal.SIGINT, create_handle_signal(monitor_instances, config, config_observer))   
    
    return monitor_instances

if __name__ == "__main__":
    monitor_instances = start_loggifly()
    try:
        for monitor in monitor_instances.values():
            monitor.shutdown_event.wait()
    except KeyboardInterrupt:
        for monitor in monitor_instances.values():
            logging.info("KeyboardInterrupt received. Shutting down...")
            monitor.shutdown_event.set()
    
