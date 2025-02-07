import os
import yaml
import logging
import requests
import docker
import threading
import time
from datetime import datetime


threads = []


# Logging-Konfiguration
logging.basicConfig(
    level=logging.INFO,  # Ändere dies von INFO zu DEBUG
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", mode="w"),
        logging.StreamHandler()
    ]
)

def load_config():
    """
    Lädt die Konfiguration aus config.yaml und ergänzt sie mit Umgebungsvariablen.
    """
    config = {}
    try:
        with open("testing/config.yaml", "r") as file:
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
    }
    config["containers"] = config.get("containers", [])
    #config["keywords"] = config.get("keywords", ["error", "warning", "critical"])
    return config

def log_attachment(container):
    lines = 100
    file_name = f"last_{lines}_log-lines_from_{container.name}.txt"
    log_tail = container.logs(tail=lines).decode("utf-8")
    with open(file_name, "w") as file:  
        file.write(log_tail)
        return file_name

def send_ntfy_notification(config, container_name, message, file_name=None):
    """
    Sendet eine Benachrichtigung an den ntfy-Server.
    """
    ntfy_url = config["ntfy"]["url"]
    ntfy_topic = config.get("containers", {}).get("nextcloud", {}).get("ntfy-topic") or config.get("ntfy", {}).get("topic", "")
    ntfy_token = config["ntfy"]["token"]

    if not ntfy_url or not ntfy_topic or not ntfy_token:
        logging.error("Ntfy-Konfiguration fehlt. Benachrichtigung nicht möglich.")
        return

    headers = {
        "Authorization": f"Bearer {ntfy_token}",
        "Tags": f"warning",
    }

    message_text = f"[{container_name}] {message}"
    
    try:
        if file_name:
            # Wenn eine Datei angegeben wurde, sende diese
            headers["Filename"] = file_name
            with open(file_name, "rb") as file:
                response = requests.post(
                    f"{ntfy_url}/{ntfy_topic}", 
                    data=file,
                    headers=headers
                )
        else:
            # Wenn keine Datei angegeben wurde, sende nur die Nachricht
            response = requests.post(
                f"{ntfy_url}/{ntfy_topic}", 
                data=message_text,
                headers=headers
            )
        if response.status_code == 200:
            logging.info("Ntfy-Notification sent successfully: %s", message)
        else:
            logging.error("Error while trying to send ntfy-notification: %s", response.text)
    except requests.RequestException as e:
        logging.error("Error while trying to connect to ntfy: %s", e)

def monitor_container_logs(config, container, keywords, keywords_with_file, timeout=30):
    """
    Überwacht die Logs eines Containers und sendet Benachrichtigungen bei Schlüsselwörtern.
    """
    now = datetime.now()
    start_time = 0
    containerr = container.name
    print(f"contaaaaaainer: {containerr}")
    rate_limit = 10

    if isinstance(config["containers"][container.name], list):
        keywords.extend(config["containers"][container.name])
    
    if isinstance(config["containers"][container.name], dict):
        if "send-log-file" and "no-log-file" in config["containers"][container.name]:
            keywords.extend(config["containers"][container.name]["no-log-file"])
            keywords_with_file.extend(config["containers"][container.name]["send-log-file"])
    else:
        logging.error("Error in config: not a list or not a properly confifured dict with send-log-file and no-log-file attributes")

    try:
        log_stream = container.logs(stream=True, follow=True, since=now)
        logging.info("Monitoring for Container started: %s", container.name)

        for log_line in log_stream:
            try:
                # Stelle sicher, dass log_line_decoded ein String ist
                log_line_decoded = str(log_line.decode("utf-8")).strip()
                #logging.info("[%s] %s", container.name, log_line_decoded)

                # Prüfe ob log_line_decoded nicht leer ist
                if log_line_decoded:
                    # Schlüsselwörter mit file überprüfen
                    if any(str(keyword) in log_line_decoded for keyword in keywords_with_file):
                        if time.time() - start_time >= rate_limit:
                            logging.info(f"waiting {start_time - time.time()}")
                            logging.info("Keyword (with attachment) was found in %s: %s", container.name, log_line_decoded)
                            file_name = log_attachment(container)
                            send_ntfy_notification(config, container.name, log_line_decoded, file_name)
                            start_time = time.time()
                        # Schlüsselwörter ohne file überprüfen
                    if any(str(keyword) in log_line_decoded for keyword in keywords):
                        if time.time() - start_time >= rate_limit:
                            logging.info(f"waiting {start_time - time.time()}")
                            logging.info("Keyword was found in %s: %s", container.name, log_line_decoded)
                            send_ntfy_notification(config, container.name, log_line_decoded)
                            time.sleep(rate_limit)
                            start_time = time.time()



            except UnicodeDecodeError:
                logging.warning("Fehler beim Dekodieren einer Log-Zeile von %s", container.name)
    except docker.errors.APIError as e:
        logging.error("Docker API-Fehler für Container %s: %s", container.name, e)
    except Exception as e:
        logging.error("Fehler bei der Überwachung von %s: %s", container.name, e)
        # Füge hier zusätzliches Logging hinzu
        logging.error("Fehlerdetails: %s", str(e.__class__.__name__))
        
    logging.info("Monitoring stopped for Container: %s", container.name)

def monitor_docker_logs(config):
    """
    Erstellt Threads zur Überwachung der Container-Logs.
    """
    global threads
    global_keywords = [ ]
    global_keywords_with_file = [ ]
    if isinstance(config.get("global-keywords"), list):
        global_keywords = config["global-keywords"]
        
    elif isinstance(config.get("global-keywords"), dict):
        if "send-log-file" and "no-log-file" in config["global-keywords"]:
            global_keywords = (config["global-keywords"]["no-log-file"])
            global_keywords_with_file = (config["global-keywords"]["send-log-file"])
        else:
            logging.error("Error in config: global-keywords: 'send-log-file' or 'no-log-file' not properly configured")

    client = docker.from_env()
    monitored_containers = [ ]
    for container in config["containers"]:
        monitored_containers.append(container)
    containers = client.containers.list()
    selected_containers = [c for c in containers if c.name in monitored_containers]

    logging.info("Ausgewählte Container zur Überwachung: %s", [c.name for c in selected_containers])

    for container in selected_containers:
        thread = threading.Thread(target=monitor_container_logs, args=(config, container, global_keywords, global_keywords_with_file, None))
        threads.append(thread)
        thread.start()

    logging.info("Monitoring started for all selected containers. Monitoring docker events now")
    for event in client.events(decode=True, filters={"event": "start"}):
        id = event["Actor"]["ID"]
        container_from_event = client.containers.get(id)
        if container_from_event.name in monitored_containers:
            thread = threading.Thread(target=monitor_container_logs, args=(config, container_from_event, global_keywords, global_keywords_with_file, None))
            threads.append(thread)
            thread.start()
            logging.info("Monitoring new container: %s", container_from_event.name)

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    logging.info("Logsend started")
    config = load_config()
    send_ntfy_notification(config, "Logsend:", "The programm is running and monitoring the logs of your selected containers.")
    monitor_docker_logs(config)
