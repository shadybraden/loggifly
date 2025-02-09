import requests
import logging
import os
import urllib.parse


logging.basicConfig(
    level=logging.DEBUG,  # Ändere dies von INFO zu DEBUG
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", mode="w"),
        logging.StreamHandler()
    ]
)



def send_ntfy_notification(config, container_name, message, keyword, file_name=None):
    """
    Sendet eine Benachrichtigung an den ntfy-Server.
    """
    ntfy_url = config["ntfy"]["url"]
    ntfy_token = config["ntfy"]["token"]

    if isinstance(config.get("containers").get(container_name, {}), dict):
        ntfy_topic = config.get("containers", {}).get(container_name, {}).get("ntfy-topic") or config.get("ntfy", {}).get("topic", "")
        ntfy_tags = config.get("containers", {}).get(container_name, {}).get("ntfy-tags") or config.get("ntfy", {}).get("tags", "warning")

    # else:
    #     ntfy_topic = config.get("ntfy", {}).get("topic", "")
    #     ntfy_tags = config.get("ntfy", {}).get("tags", "warning")
   

    if not ntfy_url or not ntfy_topic or not ntfy_token:
        logging.error("Ntfy-Konfiguration fehlt. Benachrichtigung nicht möglich.")
        return

    headers = {
        "Authorization": f"Bearer {ntfy_token}",
        "Tags": f"{ntfy_tags}",
        "Icon": "icon.png"
    }

    if keyword is not None:
        headers["Title"] = f"{container_name}"
    else:
        headers["Title"] = f"'{keyword}' found in {container_name}"


    message_text = f"{message}"
    
    try:
        if file_name:
            # Wenn eine Datei angegeben wurde, sende diese
            logging.debug("Message WITH file is being sent")
            headers["Filename"] = file_name
            with open(file_name, "rb") as file:
                response = requests.post(
                    f"{ntfy_url}/{ntfy_topic}?message={urllib.parse.quote(message_text)}",
                    data=file,
                    headers=headers
                )
            if os.path.exists(file_name):
                os.remove(file_name)
                logging.debug(f"Die Datei {file_name} wurde gelöscht.")
            else:
                logging.debug(f"Die Datei {file_name} existiert nicht.")
        else:
            # Wenn keine Datei angegeben wurde, sende nur die Nachricht
            logging.debug("Message WITHOUT file is being sent")

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


# if __name__ == "__main__":
#     send_ntfy_notification()