import requests
import apprise
import base64
import logging
from pydantic import SecretStr
import urllib.parse
from load_config import GlobalConfig

logging.getLogger(__name__)

def get_ntfy_config(config, message_config, container_config):

    ntfy_config = {"topic": None, 
                    "tags": None,
                    "priority": None, 
                    "url": None, 
                    "token": None,
                    "username": None,
                    "password": None,
                    "authorization": ""
                    }
    
    global_config = config.notifications.ntfy.model_dump(exclude_none=True) if config.notifications.ntfy else {}
    container_config = container_config.model_dump(exclude_none=True) if container_config else {}
    message_config = message_config if message_config else {}

    for key in ntfy_config.keys():
        ntfy_key = "ntfy_" + key
        if message_config.get(ntfy_key) is not None:
            ntfy_config[key] = message_config.get(ntfy_key)
        elif container_config.get(ntfy_key) is not None:
            ntfy_config[key] = container_config.get(ntfy_key)
        elif global_config.get(key) is not None:
            ntfy_config[key] = global_config.get(key)

    for key, value in ntfy_config.items():
        if value and isinstance(value, SecretStr):
            ntfy_config[key] = value.get_secret_value()

    if ntfy_config.get("token"):
        ntfy_config["authorization"] = f"Bearer {ntfy_config['token']}"
    # elif config.notifications.ntfy.username and config.notifications.ntfy.password:
    elif ntfy_config.get('username') and ntfy_config.get('password'):
        credentials = f"{ntfy_config['username']}:{ntfy_config['password']}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        ntfy_config["authorization"] = f"Basic {encoded_credentials}"
    logging.debug(f"Ntfy-Config: {ntfy_config}")
    return ntfy_config


def get_apprise_url(config, message_config, container_config):
    apprise_url = None
    global_config = config.notifications.apprise.model_dump(exclude_none=True) if config.notifications.apprise else {}
    container_config = container_config.model_dump(exclude_none=True) if container_config else {}
    message_config = message_config if message_config else {}

    if message_config.get("apprise_url"):
        apprise_url = message_config.get("apprise_url")
    elif container_config.get("apprise_url"):
        apprise_url = container_config.get("apprise_url")
    elif global_config.get("url"):
        apprise_url = global_config.get("url")

    if apprise_url and isinstance(apprise_url, SecretStr):
        apprise_url = apprise_url.get_secret_value() if apprise_url else None

    logging.debug(f"Apprise-URL: {apprise_url}")
    return apprise_url

def get_webhook_config(config, message_config, container_config):
    webhook_config = {"url": None, "headers": {}}
    
    global_config = config.notifications.webhook.model_dump(exclude_none=True) if config.notifications.webhook else {}
    container_config = container_config.model_dump(exclude_none=True) if container_config else {}
    message_config = message_config if message_config else {}

    for key in webhook_config.keys():
        webhook_key = "webhook_" + key
        if message_config.get(webhook_key) is not None:
            webhook_config[key] = message_config.get(webhook_key)
        elif container_config.get(webhook_key) is not None:
            webhook_config[key] = container_config.get(webhook_key)
        elif global_config.get(key) is not None:
            webhook_config[key] = global_config.get(key)
    
    logging.debug(f"Webhook-Config: {webhook_config}")
    return webhook_config


def send_apprise_notification(url, message, title, file_path=None):
    apobj = apprise.Apprise()
    apobj.add(url)
    message = ("This message had to be shortened: \n" if len(message) > 1900 else "") + message[:1900]
    try: 
        if file_path is None:
            apobj.notify(
                title=title,
                body=message,
            )
        else:
            apobj.notify(
                title=title,
                body=message,
                attach=file_path
            )
        logging.info("Apprise-Notification sent successfully")
    except Exception as e:
        logging.error("Error while trying to send apprise-notification: %s", e)


def send_ntfy_notification(ntfy_config, message, title, file_path=None):
    message = ("This message had to be shortened: \n" if len(message) > 3900 else "") + message[:3900]
    headers = {
        "Title": title,
        "Tags": f"{ntfy_config['tags']}",
        "Icon": "https://raw.githubusercontent.com/clemcer/loggifly/main/images/icon.png",
        "Priority": f"{ntfy_config['priority']}"
        }
    if ntfy_config.get('authorization'):
        headers["Authorization"] = f"{ntfy_config.get('authorization')}"

    try:
        if file_path:
            file_name = file_path.split("/")[-1]
            headers["Filename"] = file_name
            with open(file_path, "rb") as file:
                if len(message) < 199:
                    response = requests.post(
                        f"{ntfy_config['url']}/{ntfy_config['topic']}?message={urllib.parse.quote(message)}",
                        data=file,
                        headers=headers
                    )
                else:
                    response = requests.post(
                        f"{ntfy_config['url']}/{ntfy_config['topic']}",
                        data=file,
                        headers=headers
                    )
        else:
            response = requests.post(
                f"{ntfy_config['url']}/{ntfy_config['topic']}", 
                data=message,
                headers=headers
            )
        if response.status_code == 200:
            logging.info("Ntfy-Notification sent successfully")
        else:
            logging.error("Error while trying to send ntfy-notification: %s", response.text)
    except requests.RequestException as e:
        logging.error("Error while trying to connect to ntfy: %s", e)


def send_webhook(json_data, webhook_config):
    url, headers = webhook_config.get("url"), webhook_config.get("headers", {})
    try: 
        response = requests.post(
            url=url,
            headers=headers,
            json=json_data,
            timeout=10
            )
        if response.status_code == 200:
            logging.info(f"Webhook sent successfully.")
            #logging.debug(f"Webhook Response: {json.dumps(response.json(), indent=2)}")
        else:
            logging.error("Error while trying to send POST request to custom webhook: %s", response.text)
    except requests.RequestException as e:
        logging.error(f"Error trying to send webhook to url: {url}, headers: {headers}: %s", e)


def send_notification(config: GlobalConfig, container_name, title=None, message=None, message_config=None, container_config=None, hostname=None):
    message = message.replace(r"\n", "\n").strip() if message else ""
    # When multiple hosts are set the hostname is added to the title, when only one host is set the hostname is an empty string
    title = f"[{hostname}] - {title}" if hostname else title
    file_path = message_config.get("file_path") if message_config else None

    ntfy_config = get_ntfy_config(config, message_config, container_config)
    if (ntfy_config and ntfy_config.get("url") and ntfy_config.get("topic")):
        send_ntfy_notification(ntfy_config, message=message, title=title, file_path=file_path)

    apprise_url = get_apprise_url(config, message_config, container_config)
    if apprise_url:
        send_apprise_notification(apprise_url, message=message, title=title, file_path=file_path)

    webhook_config = get_webhook_config(config, message_config, container_config)
    if (webhook_config and webhook_config.get("url")):
        keywords = message_config.get("keywords_found", None) if message_config else None
        json_data = {"container": container_name, "keywords": keywords, "title": title, "message": message, "host": hostname}
        send_webhook(json_data, webhook_config)

