import logging
import docker
import requests
import threading
import os
import signal
import sys
import time
from notifier import send_notification
from docker.tls import TLSConfig
from urllib.parse import urlparse
from pydantic import ValidationError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from load_config import load_config, format_pydantic_error
from docker_monitor import DockerLogMonitor



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


def create_handle_signal(monitor_instances, config, config_observer):
    def handle_signal(signum, frame):
        if not config.settings.disable_shutdown_message:
            send_notification(config, "LoggiFly", "LoggiFly", "Shutting down")
        for monitor in monitor_instances:
            monitor.shutdown_event.set()
            threading.Thread(target=monitor.cleanup).start()
        if config_observer is not None:
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
                self.config, _ = load_config()
            except ValidationError as e:
                self.logger.critical(f"Error reloading Config (using old config) {format_pydantic_error(e)}")

            for monitor in self.monitor_instances.values():
                monitor.reload_config(self.config)
            self.last_config_reload_time = time.time()  


def start_config_watcher(monitor_instances, config, path):
    observer = Observer()
    observer.schedule(ConfigHandler(monitor_instances, config), path=path, recursive=False)
    observer.start()
    return observer
    
def check_client_connection(monitor, initial_client, tls_config, host, label):
    current_client = {"client": initial_client}

    def try_to_connect():
        RECONNECT_COOLDOWN = 60
        while True:
            try:
                if current_client["client"].ping():
                    logging.info(f"Successfully reconnected to Docker Host: {host} ({label})")
                    return True
            except:
                pass
            try:
                new_client = docker.DockerClient(base_url=host, tls=tls_config)
                try:
                    current_client["client"].close()
                except Exception as e:
                    logging.debug(f"Error closing old connection to Docker Host {host} ({label}): {e}")
                current_client["client"] = new_client
                logging.info(f"Successfully reconnected to Docker Host: {host} ({label})")
                return True
            except docker.errors.DockerException as e:
                logging.debug(f"Could not reconnect to Docker Host {host} ({label}): {e}")
            except Exception as e:
                logging.error(f"Could not reconnect to Docker Host: {host} ({label}). Unexpected error: {e}")
            time.sleep(RECONNECT_COOLDOWN)

    def handle_error(error_count, last_error_time, host):
        MAX_ERRORS = 5
        ERROR_WINDOW = 120
        now = time.time()

        if now - last_error_time > ERROR_WINDOW:
            error_count = 0
            last_error_time = now
        error_count += 1

        if error_count > MAX_ERRORS:
            logging.error(f"Max errors reached for {host} ({label}). Count: {error_count}")
            return error_count, last_error_time, False
        return error_count, last_error_time, True

    def ping_docker_client():
        error_count = 0
        last_error_time = time.time()
        while True:
            connected = True
            ping = False
            try:
                ping = current_client["client"].ping()
                if not ping:
                    error_count, last_error_time, connected = handle_error(error_count, last_error_time, host)
                    logging.debug(f"Could not ping docker client for {host} ({label})")
                # else:
                #     logging.debug(f"Ping successful for {host}")
            except (docker.errors.APIError, requests.exceptions.ConnectionError) as e:
                error_count, last_error_time, connected = handle_error(error_count, last_error_time, host)
                logging.debug(f"Could not ping docker host: {host} ({label}). Connection Error: {e}")
            except Exception as e:
                error_count, last_error_time, connected = handle_error(error_count, last_error_time, host)
                logging.error(f"Could not ping docker host {host} ({label}): Unexpected Error: {e}")
            finally:
                if not connected:
                    logging.error(f"Connection lost to Docker Host: {host} ({label}). Trying to reconnect every 60s now...")
                    monitor.cleanup()
                    try:
                        current_client["client"].close()
                    except Exception as e:
                        logging.debug(f"Error closing client: {e}")
                    success = try_to_connect()
                    if success:
                        monitor.shutdown_event.clear()
                        monitor.start(current_client["client"])
                        error_count = 0 
                if ping:
                    time.sleep(10)
                else:
                    time.sleep(1 + error_count * 0.5)  

    thread = threading.Thread(target=ping_docker_client, daemon=True)
    thread.start()
    return thread

def create_docker_clients():
    """
    This function creates Docker clients for all hosts specified in the DOCKER_HOST environment variables + the mounted docker socket.
    When the port 2376 is used TLS certificates are searched in '/certs/{ca,cert,key}'.pem 
    or '/certs/{host}/{ca,cert,key}.pem' (to use in case of multiple hosts) with {host} being the IP or FQDN of the host.
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
    tmp_hosts = [h.strip() for h in docker_host.split(",") if h.strip()]
    hosts = []
    for host in tmp_hosts:
        label = None
        if "|" in host:
            host, label = host.split("|", 1)
        hosts.append((host, label.strip()) if label else (host.strip(), None))

    if os.path.exists("/var/run/docker.sock"):
        hosts.append("unix:///var/run/docker.sock")

    clients = []

    for host, label in hosts:
        logging.debug(f"Creating Docker Client for {host}")
        parsed = urlparse(host)
        tls_config = None
        if parsed.scheme == "unix":
            pass
        elif parsed.scheme == "tcp":
            hostname = parsed.hostname
            tls_config = get_tls_config(hostname)
        try:
            client = docker.DockerClient(base_url=host, tls=tls_config)
            clients.append((client, tls_config, host, label))
        except docker.errors.DockerException as e:
            logging.error(f"Error creating Docker client for {host}: {e}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error creating Docker client for {host}: {e}")
            continue

    logging.info(f"Connections to Docker-Clients established for {', '.join([client[2] for client in clients])}"
                 if len(clients) > 1 else "Connected to Docker Client")
    return clients


def start_loggifly():
    try:
        config, path = load_config()
    except ValidationError as e:
        logging.critical(f"Error loading Config: {format_pydantic_error(e)}")
        logging.info("Waiting 15s to prevent restart loop...")
        time.sleep(15)
        sys.exit(1)

    logging.getLogger().setLevel(getattr(logging, config.settings.log_level.upper(), logging.INFO))
    logging.info(f"Log-Level set to {config.settings.log_level}")

    clients = create_docker_clients()
    client_values = {}
    hostname = ""
    for number, (client, tls_config, host, label) in enumerate(clients, start=1):
        client_values[host] = {"client": client, "tls_config": tls_config, "label": label, "host": host}
        if len(clients) > 1:
            try:
                hostname = label if label else client.info()["Name"]
            except Exception as e:
                hostname = f"Host-{number}"
                logging.warning(f"Could not get hostname for {host}. LoggiFly will call this host '{hostname}' in notifications and in logging to differentiate it from the other hosts."
                    f"\nThis error might have been raised because you are using a Socket Proxy without the environment variable 'INFO=1'"
                    f"\nYou can also set a label for the docker host in the DOCKER_HOST environment variable like this: 'tcp://host:2375|label' to use instead of the hostname."
                    f"\nError details: {e}")    
                                
        logging.info(f"Starting monitoring for {host} {'(' + hostname + ')' if hostname else ''}")
        monitor = DockerLogMonitor(config, hostname)
        monitor.start(client)   
        client_values[host]["monitor"] = monitor
 
    for host, values in client_values.items():
        check_client_connection(values["monitor"], values["client"], values["tls_config"], host, values["label"])

    monitor_instances = [client_values[host]["monitor"] for host in client_values.keys()]
    if isinstance(path, str) and os.path.exists(path):
        config_observer = start_config_watcher(monitor_instances, config, path)
    else:
        logging.debug("Config watcher is not started because no valid config path exist.")
        config_observer = None

    signal.signal(signal.SIGTERM, create_handle_signal(monitor_instances, config, config_observer))
    signal.signal(signal.SIGINT, create_handle_signal(monitor_instances, config, config_observer))   
    return monitor_instances  # return the monitor instances

if __name__ == "__main__":
    monitor_instances = start_loggifly()
    try:
        for monitor in monitor_instances:
            monitor.shutdown_event.wait()
    except KeyboardInterrupt:
        for monitor in monitor_instances:
            logging.info("KeyboardInterrupt received. Shutting down...")
            monitor.shutdown_event.set()
    
