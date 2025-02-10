import os
import yaml
import re
import logging
import docker
import threading
import time
import traceback
import signal
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from notifier import send_ntfy_notification


shutdown_event = threading.Event()

def set_logging(config):
    log_level = os.getenv("LOG_LEVEL", config.get("settings", {}).get("log-level", "INFO")).upper()
    logging.getLogger().handlers.clear()
    logging.basicConfig(
        level = getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("monitor.log", mode="w"),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Log-Level set to {log_level}")
    logging.debug("This is a Debug-Message")
    logging.info("This is a Info-Message")
    logging.warning("This is a Warning-Message")

def handle_signal(signum, frame):
    send_ntfy_notification(config, "Logsend:", "The programm is shutting down.")
    logging.info(f"Signal {signum} received. shutting down...")
    shutdown_event.set() 

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)




def load_config():
    """
    Lädt die Konfiguration aus config.yaml und ergänzt sie mit Umgebungsvariablen.
    """
    config = {}
    try:
        with open("config.yaml", "r") as file:
            config = yaml.safe_load(file)
            logging.info("Konfigurationsdatei erfolgreich geladen.")
    except FileNotFoundError:
        logging.warning("config.yaml nicht gefunden. Verwende nur Umgebungsvariablen.")

    # Ergänze oder überschreibe Konfigurationswerte mit Umgebungsvariablen
    config["ntfy"] = {
        "url": os.getenv("NTFY_URL", config.get("ntfy", {}).get("url", "")),
        "topic": os.getenv("NTFY_TOPIC", config.get("ntfy", {}).get("topic", "")),
        "token": os.getenv("NTFY_TOKEN", config.get("ntfy", {}).get("token", "")),
        "priority": os.getenv("NTFY_PRIORITY", config.get("ntfy", {}).get("priority", "default")),
        "tags": os.getenv("NTFY_TAG", config.get("ntfy", {}).get("tags", "warning")),
    }
    config["containers"] = config.get("containers", [])
    #config["keywords"] = config.get("keywords", ["error", "warning", "critical"])
    return config


def restart_docker_container():
    logging.debug("restart_docker_container function was called")
    time.sleep(5)
    client = docker.from_env()
    container_id = os.getenv("HOSTNAME")  # Docker setzt HOSTNAME auf die Container-ID
    container = client.containers.get(container_id)
    logging.debug(f"container_id: {container_id}, container: {container}")
    container.restart()


class ConfigHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('config.yaml'):
            logging.debug("File has changed!")
            logging.info("Restarting container in 5s")
            restart_docker_container()


def detect_config_changes():
    logging.debug("watching for config changes")
    path = "/app/config.yaml"  # Pfad zur config.yaml
    event_handler = ConfigHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path, recursive=False)    
    observer.start()
    try:
        while not shutdown_event.is_set():
            observer.join(1)
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        observer.stop()
        observer.join()


def log_attachment(container):
    lines = 50
    file_name = f"last_{lines}_log-lines_from_{container.name}.txt"

    log_tail = container.logs(tail=lines).decode("utf-8")
    with open(file_name, "w") as file:  
        file.write(log_tail)
        return file_name

def monitor_container_logs(config, client, container, keywords, keywords_with_file):
    """
    Überwacht die Logs eines Containers und sendet Benachrichtigungen bei Schlüsselwörtern.
    """
    now = datetime.now()
    start_time = 0
    keyword_notification_cooldown = os.getenv("keyword_notification_cooldown", config.get("settings", {}).get("keyword_notification_cooldown", 10))
    logging.debug(f"keyword_notification_cooldown: {keyword_notification_cooldown}")
    local_keywords = keywords.copy()
    local_keywords_with_file = keywords_with_file.copy()

    container_config = config.get("containers", {}).get(container.name)
    if container_config is None:
        container_config = []

    if isinstance(config["containers"][container.name], list):
        local_keywords.extend(config["containers"][container.name])
    elif isinstance(config["containers"][container.name], dict):
        if "keywords_with_attachment" in config["containers"][container.name]:
            local_keywords_with_file.extend(config["containers"][container.name]["keywords_with_attachment"])
        if "keywords" in config["containers"][container.name]:
            local_keywords.extend(config["containers"][container.name]["keywords"])
    else:
        logging.error("Error in config: not a list or dict not  properly configured with keywords_with_attachment and keywords attributes")

    time_per_keyword = { }
    for keyword in local_keywords + local_keywords_with_file:
        if isinstance(keyword, dict) and keyword.get("regex") is not None:
            time_per_keyword[keyword["regex"]] = 0
        else:
            time_per_keyword[keyword] = 0
    logging.debug(f"{container.name}: time_per_keyword: {time_per_keyword}")
    logging.debug(f"starting log stream for {container.name}")
    try:
        log_stream = container.logs(stream=True, follow=True, since=now)
        logging.info("Monitoring for Container started: %s", container.name)

        for log_line in log_stream:
            if shutdown_event.is_set():
                logging.debug(f"Noticed that shutdown_event.is_set in monitor_container_logs() function for {container.name}. Closing client now")
                client.close()
                break
            try:
                log_line_decoded = str(log_line.decode("utf-8")).strip()
                #logging.debug("[%s] %s", container.name, log_line_decoded)
                if log_line_decoded:
                    # keywords with file 
                    for keyword in local_keywords_with_file:
                                ## Regex-Keyword
                        if isinstance(keyword, dict) and keyword.get("regex") is not None:
                            keyword = keyword["regex"]
                            logging.debug(f"Testing regex: {keyword} against line: {log_line_decoded}")
                            if time.time() - time_per_keyword[keyword] >= int(keyword_notification_cooldown):
                                if re.search(keyword, log_line_decoded, re.IGNORECASE):
                                    logging.info(f"waiting {start_time - time.time()} for {keyword}")
                                    logging.info(f"Regex-Keyword (with attachment) '{keyword}' was found in {container.name}: {log_line_decoded}")
                                    file_name = log_attachment(container)
                                    send_ntfy_notification(config, container.name, log_line_decoded, keyword, file_name)
                                    time_per_keyword[keyword] = time.time()
                            ## Normal String Keyword
                        elif str(keyword) in log_line_decoded:
                            if time.time() - time_per_keyword[keyword] >= int(keyword_notification_cooldown):
                                logging.debug(f"waiting {start_time - time.time()} for {keyword}")
                                logging.info(f"Keyword (with attachment) '{keyword}' was found in {container.name}: {log_line_decoded}") 
                                file_name = log_attachment(container)
                                send_ntfy_notification(config, container.name, log_line_decoded, keyword, file_name)
                                time_per_keyword[keyword] = time.time()
                    # keywords without file 
                    for keyword in local_keywords:
                        ## Regex-Keyword
                        if isinstance(keyword, dict) and keyword.get("regex") is not None:
                            keyword = keyword["regex"]
                            logging.debug(f"Testing regex: {keyword} against line: {log_line_decoded}")
                            if time.time() - time_per_keyword[keyword] >= int(keyword_notification_cooldown):
                                if re.search(keyword, log_line_decoded, re.IGNORECASE):
                                    logging.info(f"waiting {start_time - time.time()} for {keyword}")
                                    logging.info(f"Regex-Keyword (with attachment) '{keyword}' was found in {container.name}: {log_line_decoded}")
                                    send_ntfy_notification(config, container.name, log_line_decoded, keyword)
                                    time_per_keyword[keyword] = time.time()
                            ## Normal String Keyword
                        elif str(keyword) in log_line_decoded:
                            if time.time() - time_per_keyword[keyword] >= int(keyword_notification_cooldown):
                                logging.debug(f"waiting {start_time - time.time()} for {keyword}")
                                logging.info(f"Keyword (with attachment) '{keyword}' was found in {container.name}: {log_line_decoded}") 
                                send_ntfy_notification(config, container.name, log_line_decoded, keyword)
                                time_per_keyword[keyword] = time.time()

            except UnicodeDecodeError:
                logging.warning("Fehler beim Dekodieren einer Log-Zeile von %s", container.name)
    except docker.errors.APIError as e:
        logging.error("Docker API-Fehler für Container %s: %s", container.name, e)
    except Exception as e:
        logging.error("Fehler bei der Überwachung von %s: %s", container.name, e)
        # Füge hier zusätzliches Logging hinzu
        logging.error("Fehlerdetails: %s", str(e.__class__.__name__))
        logging.debug(traceback.format_exc())


    logging.info("Monitoring stopped for Container: %s", container.name)

def monitor_docker_logs(config):
    """
    Erstellt Threads zur Überwachung der Container-Logs.
    """
    threads = []

    global_keywords = [ ]
    global_keywords_with_file = [ ]
    if isinstance(config.get("global_keywords"), list):
        global_keywords = config["global_keywords"] 
    elif isinstance(config.get("global_keywords"), dict):
        if "keywords_with_attachment" in config["global_keywords"]:
            global_keywords_with_file = (config["global_keywords"]["keywords_with_attachment"])
        if "keywords" in config["global_keywords"]:
            global_keywords = (config["global_keywords"]["keywords"])
        if not "keywords_with_attachment" or "keywords" in config["global_keywords"]:
            logging.error("Error in config: global_keywords: 'attachment' or 'keywords' not properly configured")



    client = docker.from_env()
    selected_containers = [ ]
    for container in config["containers"]:
        selected_containers.append(container)
    containers = client.containers.list()

    containers_to_monitor = [c for c in containers if c.name in selected_containers]

    unmonitored_containers = [c for c in selected_containers if c not in [c.name for c in containers_to_monitor]]

    logging.info(f"These containers are being monitored: {[c.name for c in containers_to_monitor]} \n \
                    These containers from your config are not running {unmonitored_containers}")

    send_ntfy_notification(config, "Logsend", f"Monitored Containers: {[c.name for c in containers_to_monitor]}, \n\n Containers not running: {unmonitored_containers}")
    for container in containers_to_monitor:
        thread = threading.Thread(target=monitor_container_logs, args=(config, client, container, global_keywords, global_keywords_with_file), daemon=True)
        threads.append(thread)
        thread.start()

    thread_file_change = threading.Thread(target=detect_config_changes)
    threads.append(thread_file_change)
    thread_file_change.start()

    logging.info("Monitoring started for all selected containers. Monitoring docker events now to watch for new containers")

    for event in client.events(decode=True, filters={"event": "start"}):
        if shutdown_event.is_set():
            logging.debug(f"Noticed that shutdown_event.is_set in monitor_docker_logs() function. Closing client now")
            client.close()
            break
        id = event["Actor"]["ID"]
        container_from_event = client.containers.get(id)
        if container_from_event.name in selected_containers:
            thread = threading.Thread(target=monitor_container_logs, args=(config, client, container_from_event, global_keywords, global_keywords_with_file), daemon=True)
            threads.append(thread)
            thread.start()
            logging.info("Monitoring new container: %s", container_from_event.name)


    for thread in threads:
        thread.join()

if __name__ == "__main__":
    logging.info("Logsend started")
    config = load_config()
    set_logging(config)
    logging.debug(config)
    send_ntfy_notification(config, "Logsend:", "The programm is running and monitoring the logs of your selected containers.")
    monitor_docker_logs(config)

