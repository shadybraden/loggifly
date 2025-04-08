import os
import logging
import docker
import threading
import traceback
import signal
import sys
import time
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
class DockerLogMonitor:
    def __init__(self):
        try:
            self.config = load_config()
        except ValidationError as e:
            logging.critical(f"Error loading Config: {format_pydantic_error(e)}")
            logging.info("Waiting 10s to prevent restart loop...")
            time.sleep(10)
            sys.exit(1)

        self._init_logging()
        self.client = docker.from_env()
        self.selected_containers = [c for c in self.config.containers]
        self.shutdown_event = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.line_processor_instances = {}
        self.processors_lock = threading.Lock()

        self.stream_connections = {}
        self.stream_connections_lock = threading.Lock()
        self.monitored_containers = {}
        
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
        self.last_config_reload_time = 0
        self.watch_events()

    def _init_logging(self):
        log_level = self.config.settings.log_level
        logging.getLogger().handlers.clear()
        logging.basicConfig(
            level = getattr(logging, log_level.upper(), logging.INFO),
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("monitor.log", mode="w"),
                logging.StreamHandler()
            ]
        )
        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)        
        logging.info(f"Log-Level set to {log_level}")

            
    class ConfigHandler(FileSystemEventHandler):
        def __init__(self, monitor):
            self.monitor = monitor
            
        def on_modified(self, event):
            if self.monitor.config.settings.reload_config and not event.is_directory and event.src_path.endswith('config.yaml'):
                self.monitor.reload_config()


    def handle_signal(self, signum, frame):
        if not self.config.settings.disable_shutdown_message:
            send_notification(self.config, "LoggiFly", "LoggiFly", "Shutting down")
        self.shutdown_event.set()
        self.cleanup()


    def reload_config(self):
        if time.time() - self.last_config_reload_time < 3:
            logging.info("Config reload skipped, waiting for 3 seconds")
            return
        logging.info("Config change detected, reloading config...")
        time.sleep(0.3)
        try:
            self.config = load_config()
        except ValidationError as e:
            logging.critical(f"Error reloading Config (using old config) {format_pydantic_error(e)}")

        if not self.config.settings.disable_config_reload_message:
            send_notification(self.config, "Loggifly", "LoggiFly", "Reloading Config...")
        try:
            self._init_logging()
            self.selected_containers = [c for c in self.config.containers]
            stop_monitoring = [c for _, c in self.monitored_containers.items() if c.name not in self.selected_containers]
            for c in stop_monitoring:
                _, container_stop_event = self.line_processor_instances[c.name]
                container_stop_event.set()
                self.close_stream_connecion(c.name)
                self.monitored_containers.pop(c.id)

            for container, instance in self.line_processor_instances.items():
                if container in self.selected_containers:
                    processor, _ = instance
                    processor.load_config_variables(self.config)

            containers_to_monitor = [c for c in self.client.containers.list() if c.name in self.selected_containers and c.id not in self.monitored_containers.keys()]
            for c in containers_to_monitor:
                logging.info(f"New Container to monitor: {c.name}")
                if self.line_processor_instances.get(c.name) is not None:
                    _, container_stop_event = self.line_processor_instances[c.name]
                    container_stop_event.clear()
                self.monitor_container(c)
                self.monitored_containers[c.id] = c

            self.start_message()
            if not self.config.settings.reload_config:
                self.observer.stop()
                self.observer.join()
                logging.info("Config watcher stopped.")
                
        except Exception as e:
            logging.error(f"Error handling config changes: {e}")

        self.last_config_reload_time = time.time()


    def start_config_watcher(self):
        self.observer = Observer()
        self.observer.schedule(self.ConfigHandler(self), path="/app/config.yaml", recursive=False)
        self.observer.start()
        self.add_thread(self.observer)

    def add_thread(self, thread):
        with self.threads_lock:
            self.threads.append(thread)

    def add_processor_instance(self, processor, container_stop_event, container_name):
        with self.processors_lock:
            if container_name not in self.line_processor_instances:
                self.line_processor_instances[container_name] = processor, container_stop_event
                return True
            else:
                return False

    def add_stream_connection(self, container_name, connection):
        with self.stream_connections_lock:
            self.stream_connections[container_name] = connection


    def close_stream_connecion(self, container_name):
        stream = self.stream_connections.get(container_name, None)
        if stream:
            try: 
                stream.close()
                self.stream_connections.pop(container_name)
            except Exception as e:
                logging.warning(f"Error trying do close stream during cleanup: {e}")
        else:
            logging.debug(f"Could not find log stream connection for container {container_name}")


    def handle_error(self, error_count, last_error_time):
            new_count = error_count + 1
            current_time = time.time()
            if current_time - last_error_time > 180:
                new_count = 1
            return new_count, current_time
    
    def monitor_container(self, container):
        
        def check_container(container_start_time):
            container.reload()
            if container.status != "running":
                return False
            if container.attrs['State']['StartedAt'] != container_start_time:
                return False
            return True
        
        def log_monitor():
            """
            I am using a buffer in case the logstream has an unfinished log line that can't be decoded correctly.
            """
            container_start_time = container.attrs['State']['StartedAt']
            logging.info(f"Monitoring for Container started: {container.name}")
            error_count = 0
            last_error_time = time.time()  
            if container.name in self.line_processor_instances:
                logging.debug(f"Re-Using old line processor")
                processor, container_stop_event = self.line_processor_instances[container.name]
                processor._start_flush_thread()
            else:
                container_stop_event = threading.Event()
                processor = LogProcessor(self.config, container, container_stop_event)
                self.add_processor_instance(processor, container_stop_event, container.name)
            container_stop_event.clear()
            while not self.shutdown_event.is_set():
                logging.debug(f"Starting Log Stream for {container.name}")
                buffer = b""
                try:
                    now = datetime.now()
                    log_stream = container.logs(stream=True, follow=True, since=now)
                    self.add_stream_connection(container.name, log_stream)
                    logging.info(f"Started Log Stream for {container.name}")
                    for chunk in log_stream:
                        MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB
                        buffer += chunk
                        if len(buffer) > MAX_BUFFER_SIZE:
                            logging.error("Buffer overflow detected, resetting")
                            buffer = b""
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                log_line_decoded = str(line.decode("utf-8")).strip()
                            except UnicodeDecodeError:
                                log_line_decoded = line.decode("utf-8", errors="replace").strip()
                                logging.warning(f"{container.name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                            if log_line_decoded: 
                                processor.process_line(log_line_decoded)
                        if self.shutdown_event.is_set():
                            break
                    logging.debug(f"checking container {container.name}")
                    if not check_container(container_start_time):
                        break

                except docker.errors.NotFound as e:
                    logging.error(F"Log Stream: Container {container} not found: {e}")
                    error_count, last_error_time = self.handle_error(error_count, last_error_time) 
                except docker.errors.APIError as e:
                    error_count, last_error_time = self.handle_error(error_count, last_error_time)
                except Exception as e:
                    logging.error("Error while trying to monitor %s: %s", container.name, e)
                    logging.error("Error details: %s", str(e.__class__.__name__))
                    logging.debug(traceback.format_exc())
                    error_count, last_error_time = self.handle_error(error_count, last_error_time)
                finally:
                    if self.shutdown_event.is_set() or container_stop_event.is_set():   
                        try:
                            logging.debug("Shutdown event or restart event is set. Closing log stream.")
                            log_stream.close()  
                        except Exception as e:
                            logging.debug(f"Error closing stream: Container {container.name}: {str(e)}")
                        break
                    if not check_container(container_start_time):
                        logging.debug(f"Container {container.name} is not running or was restarted. Getting rid of old thread")
                        try:
                            log_stream.close()
                        except Exception as e:
                            logging.error(f"Could not close Log Stream for container {container.name}")
                        break
                    # if there are more than 5 errors in one minute the while loop stops
                    if time.time() - last_error_time > 60:
                        error_count = 0
                    if error_count > 5:
                        logging.error(f"Error trying to establish Log Stream for {container.name}. Critical error threshold (6) reached.")
                        log_stream.close()  
                        container_stop_event.set() # to stop flush threads
                        break
                    logging.info(f"Log Stream stopped for Container: {container.name}. Reconnecting...")
            logging.info("Monitoring stopped for Container: %s", container.name)
            container_stop_event.set()


        thread = threading.Thread(target=log_monitor, daemon=True)
        self.add_thread(thread)
        thread.start()

    def start(self):
        running_containers = self.client.containers.list()
        containers_to_monitor = [c for c in running_containers if c.name in self.selected_containers]
        
        for container in containers_to_monitor:
            self.monitor_container(container)
            self.monitored_containers[container.id] = container
        
        self.start_message()
        if self.config.settings.reload_config:
            self.start_config_watcher()


    def start_message(self):
        monitored_containers_message = "\n - ".join(c.name for id, c in self.monitored_containers.items())
        unmonitored_containers = [c for c in self.selected_containers if c not in [c.name for id, c in self.monitored_containers.items()]]
        unmonitored_containers_message = "\n - ".join(unmonitored_containers) if unmonitored_containers else ""
        logging.info(f"These containers are being monitored:\n - {monitored_containers_message}")
        if unmonitored_containers:
            unmonitored_containers_str = "\n - ".join(unmonitored_containers)
            logging.info(f"These selected Containers are not running:\n - {unmonitored_containers_str}")
        else:
            unmonitored_containers_str = ""

        if self.config.settings.disable_start_message is False:
            send_notification(self.config, "loggifly", "LoggiFly", 
                              f"""The program is running and monitoring these selected Containers:\n - {monitored_containers_message}
                              \nThese selected Containers are not running:\n - {unmonitored_containers_message}"""
                              )


    def watch_events(self):
        def event_handler():
            error_count = 0
            last_error_time = time.time()
            while not self.shutdown_event.is_set():# and not self.restarting_event.is_set():
                now = time.time()
                try: 
                    for event in self.client.events(decode=True, filters={"event": ["start", "stop"]}, since=now): #["start", "stop"]}):
                        if self.shutdown_event.is_set():
                            logging.debug("Shutdown event is set. Stopping event handler.")
                            break
                        container = self.client.containers.get(event["Actor"]["ID"])
                        if event.get("Action") == "start":
                            if container.name in self.selected_containers:
                                logging.info("Monitoring new container: %s", container.name)
                                send_notification(self.config, "Loggifly", "LoggiFly", f"Monitoring new container: {container.name}")
                                self.monitor_container(container)
                                self.monitored_containers[container.id] = container
                        elif event.get("Action") == "stop":
                            if container.id in self.monitored_containers:
                                logging.debug(f"Event Handler: {container.name} stopped")
                                self.close_stream_connecion(container.name)
                                self.monitored_containers.pop(container.id)
                                _, container_stop_event = self.line_processor_instances[container.name]
                                container_stop_event.set()
                                
                except docker.errors.NotFound as e:
                    logging.error(F"Event-Handler: Container {container} not found: {e}")
                    break
                except Exception as e:  
                    if self.shutdown_event.is_set():
                        break
                    logging.error(f"Event-Handler was stopped {e}. Trying to restart it.")
                    error_count, last_error_time = self.handle_error(error_count, last_error_time)
                finally:
                    if self.shutdown_event.is_set():
                        logging.debug("Event handler is shutting down.")
                        break
                    if error_count > 5:
                        logging.error(f"Error trying to read docker events. Critical error threshold (6) reached.")
                        break
                    logging.debug(f"Restarting Event Handler")
            logging.debug("Event handler stopped.")

        logging.info("Watching for new containers...")
        thread = threading.Thread(target=event_handler, daemon=True)
        self.add_thread(thread)
        thread.start()
    

    def cleanup(self):
        stream_connections = self.stream_connections.copy()        
        
        with self.stream_connections_lock:
            for container, _ in self.stream_connections.copy().items():
                self.close_stream_connecion(container)
            logging.debug(f"No Log Stream Connections left" if len(stream_connections) ==0 else f"{len(stream_connections)} Log Stream Connections remaining")

        with self.threads_lock:
            alive_threads = []
            for thread in self.threads[::-1]:
                if isinstance(thread, Observer):
                    thread.stop()
                if thread is not threading.current_thread() and thread.is_alive():
                    thread.join(timeout=1.5)
                    if thread.is_alive():
                        logging.debug(f"Thread {thread.name} could not be stopped")
                        alive_threads.append(thread)
            self.threads = alive_threads
        try:
            self.client.close()
            logging.info("Shutdown completed")
        except Exception as e:
            logging.warning(f"Error while trying do close docker client connection during cleanup: {e}")
        # logging.debug(f"Threads still alive {len(alive_threads)}: {alive_threads}")
        # logging.debug(f"Threading Enumerate: {threading.enumerate()}")


if __name__ == "__main__":
    monitor = DockerLogMonitor()
    try:
        monitor.start()
        while not monitor.shutdown_event.is_set():
            monitor.shutdown_event.wait(2.5)
    except KeyboardInterrupt:
        monitor.shutdown_event.set()
