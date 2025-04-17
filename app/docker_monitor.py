import logging
import docker
import threading
import traceback
import time
import random
from datetime import datetime
from notifier import send_notification
from line_processor import LogProcessor




class DockerLogMonitor:
    """
    In this class a thread is started for every container that is running and set in the config 
    One thread is started to monitor docker events to watch for container starts/stops to start or stop the monitoring of containers.
    There are a few collections that are referenced between functions I want to document here:

        - self.line_processor_instances: Dict keyed by container.name, each containing a dict with {'processor' processor, 'container_stop_event': container_stop_event}
            - processor is an instance of the LogProcessor class (line_processor.py) and is gets fed the log lines from the container one by one to search for keywords among other things.
                It is stored so that the reload_config_variables function can be called to update keywords, settings, etc when the config.yaml changes. 
                When a container is stopped and started again the old processor instance is re-used.
            - container_stop_event is a threading event used to stop the threads that are running to monitor one container (log_monitor (with log stream and flush thread)
        
        - self.stream_connections: Dict of log stream connections keyed by container.name (effectively releasing the blocking log stream allowing the threads to stop)
        
        - self.monitored_containers: Dict of Docker Container objects that are currently being monitored keyed by container.id
        
        - self.selected_containers: List of container names that are set in the config

        - self.threads: List of threads that are started to monitor container logs and docker events

    """
    def __init__(self, config, hostname):
        self.hostname = hostname  # empty string if only one client is being monitored, otherwise the hostname of the client do differentiate between the hosts
        self.config = config
        
        # set up logging (hostname is added when there are multiple hosts)
        self.logger = logging.getLogger(f"Monitor-{self.hostname}")
        self.logger.handlers.clear()
        handler = logging.StreamHandler()
        formatter = (logging.Formatter(f'%(asctime)s - %(levelname)s - [Host: {self.hostname}] - %(message)s') 
                     if self.hostname else logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        self.logger.propagate = False

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
                self.close_stream_connection(c.name)
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


    def close_stream_connection(self, container_name):
        stream = self.stream_connections.get(container_name)
        container_stop_event = self.line_processor_instances[container_name]["container_stop_event"]
        container_stop_event.set()
        self.logger.info(f"Closing Log Stream connection for {container_name}")
        if stream:
            try: 
                stream.close()
                self.stream_connections.pop(container_name)
            except Exception as e:
                self.logger.warning(f"Error trying do close log stream for {container_name}: {e}")
        else:
            self.logger.debug(f"Could not find log stream connection for container {container_name}")


    def handle_error(self, error_count, last_error_time, container_name=None):
        """
        Error handling for the event handler and the log stream threads.
        If there are more than 10 errors in a minute the thread is stopped.
        """
        MAX_ERRORS = 10
        ERROR_WINDOW = 60.0  
        now = time.time()
        error_count = 0 if now - last_error_time > ERROR_WINDOW else error_count + 1
        last_error_time = now

        if error_count > MAX_ERRORS:
            if container_name:
                self.logger.error(f"Too many errors for {container_name}. Count: {error_count}")
            else:
                self.logger.error(f"Too many errors for Docker Event Handler. Count: {error_count}")
            return error_count, last_error_time, True  # True = break needed

        time.sleep(random.uniform(0.9, 1.2) * error_count) # to prevent all threads from trying to reconnect at the same time
        return error_count, last_error_time, False    


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
            # except requests.exceptions.ConnectionError as ce: 
            #     self.logger.error(f"Can not connect to Container {container.name} {ce}")
            #     pass
            # except Exception as e:
            #     self.logger.error(f"Error while checking container {container.name}: {e}")
            #     self.logger.debug(traceback.format_exc())
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
                should_break = False
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
                except docker.errors.NotFound as e:
                    self.logger.error(f"Container {container} not found during Log Stream: {e}")
                    error_count, last_error_time, should_break = self.handle_error(error_count, last_error_time, container.name)
                except Exception as e:
                    error_count, last_error_time, should_break = self.handle_error(error_count, last_error_time, container.name)
                    if error_count == 1:
                        self.logger.error("Error trying to monitor %s: %s", container.name, e)
                        #self.logger.debug(traceback.format_exc())
                finally:
                    if self.shutdown_event.is_set() or container_stop_event.is_set() or should_break:   
                        self.close_stream_connection(container.name)
                        break
                    if not check_container(container_start_time):
                        break
                    self.logger.info(f"{container.name}: Log Stream stopped. Reconnecting...")
            self.logger.info(f"{container.name}: Monitoring stopped for container.")
            container_stop_event.set()

        thread = threading.Thread(target=log_monitor, daemon=True)
        self.add_thread(thread)
        thread.start()

    # This function is called from outside this class to start the monitoring
    def start(self, client):
        self.client = client
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
                self.logger.info("Docker Event Handler started. Watching for new containers...")
                now = time.time()
                should_break = False
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
                                self.close_stream_connection(container.name)

                except docker.errors.NotFound as e:
                    self.logger.error(F"EDocker Eventvent-Handler: Container {container} not found: {e}")
                except Exception as e:  
                    error_count, last_error_time, should_break = self.handle_error(error_count, last_error_time)
                    if error_count == 1:
                        self.logger.error(f"Docker Event-Handler was stopped {e}. Trying to restart it.")
                finally:
                    if self.shutdown_event.is_set() or should_break:
                        self.logger.debug("Docker Event handler is shutting down.")
                        break
                    self.logger.info(f"Docker Event Handler stopped. Reconnecting...")
            self.logger.info("Docker Event handler stopped.")

        thread = threading.Thread(target=event_handler, daemon=True)
        self.add_thread(thread)
        thread.start()
    

    def cleanup(self):    
        """
        This function is called when the program is shutting down. 
        By closing the stream connections the log stream which would otherwise be blocked until the next log line gets released allowing the threads to fninish.
        The only thread that can not easily be stopped is the event_handler, because it is is blocked.
        """  
        self.logger.info(f"Starting cleanup " f"for host {self.hostname}..." if self.hostname else "...")
        self.shutdown_event.set()
        self.logger.debug(f"shutdown_event: {self.shutdown_event.is_set()}")
        with self.stream_connections_lock:
            for container, _ in self.stream_connections.copy().items():
                self.close_stream_connection(container)
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


