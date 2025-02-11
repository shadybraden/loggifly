<a name="readme-top"></a>

<br />
<div align="center">
  <a href="clemcer/logsend">
    <img src="/icon.png" alt="Logo" width="300" height="auto">
  </a>

<h1 align="center">Loggifly</h1>

  <p align="center">
    <a href="https://github.com/clemcer/Loggifly/issues">Report Bug</a>
    ·
    <a href="https://github.com/clemcer/Loggifly/issues">Request Feature</a>
  </p>
</div>

<br>


**Loggifly** is a lightweight tool for monitoring Docker container logs and sending notifications when specific keywords are detected. It supports both plain text and regular expression (regex) keywords and can attach the last 50 lines of a log file when a match is found. 🚀

---

## 🚀 Features

- **🔍 Keyword & Regex Monitoring**: Track specific keywords or complex regex patterns in container logs.  
- **🐳 Fine-Grained Keyword Control**: You can specify keywords per container or for all containers.  
- **📁 Log Attachments**: Automatically attach a file with the last 50 log lines to notifications.  
- **⏱ Rate Limiting**: Avoid spam with per-keyword/container cooldowns.  
- **🔧 YAML Configuration**: Define containers, keywords, and notification settings in a simple config file.  
- **📤 ntfy Integration**: Send alerts to any ntfy-compatible service (self-hosted or public).
  - **🥳 Priority, Tags & Topic**: Customize notification priority, Tags/emojis and the topic globally and/or per container

---

# Loggifly Configuration 

While there are some settings you can set via environment variables most of the configuration for Loggifly happens in the config.yaml file.
You can find the installation walkthrough [here](https://github.com/clemcer/Loggifly#installation-via-docker-compose) if you are impatient and want to skip the config explanation.

---

## 📁 Basic Structure

The `config.yaml` file is divided into four main sections:
1. **ntfy configuration**: set your ntfy url, topic, token, priority and tags
2. **`containers`**: Define which containers to monitor and their specific keywords.
3. **`global_keywords`**: Keywords that apply to **all** monitored containers.
4. **`settings`**: Global settings like cooldowns and log levels.

---

## `ntfy` section

In this section you can configure your ntfy settings. URL and token are required. Tags, topic and priority have default values. They can be set globally in this section but can also be configured per container. 

## 🐳 `containers` Section

This section defines the containers you want to monitor and the keywords/regex patterns to look for.
You can also set the topic, tags and priority for your ntfy notification which will be used over the global configuration

### Example:
```yaml
containers:
  hrconvert2:
    keywords_with_attachment:
      - regex: "\\bhttp\\b"  # Case-insensitive regex for "HTTP"
      - "error"              # Plain-text keyword
  nextcloud-app-1:
    keywords_with_attachment:
      - regex: "\\b(unauthorized|permission denied)\\b"
      - "disk full"
```
### Key Details:

- Container Name: Use the exact name of the Docker container (e.g., hrconvert2).
- keywords_with_attachment:
  - A list of keywords or regex patterns to monitor.
  - If a match is found, the last 50 lines of the log are attached to the notification.
  - Use regex: for regex patterns (e.g., "\\bhttp\\b").
  - Use plain strings for exact matches (e.g., "error").

 ---
 
## 🌍 `global_keywords` Section
Keywords defined here apply to all containers being monitored.
### Example:

```yaml

global_keywords:
  - regex: "\\b(critical|panic)\\b"  # Match "critical" or "panic" in any container
  - "out of memory"                  # Plain-text keyword
```

### Key Details:
- Global Scope: These keywords are checked in all containers.
- Same Syntax: Use regex: for patterns or plain strings for exact matches.

---

## ⚙️ `settings` Section

This section defines global behavior for Loggifly.

### Example:

```yaml
settings:
  keyword_notification_cooldown: 5  # Cooldown (in seconds) between notifications per keyword
  log_level: "INFO"                 # Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
```

### Key Details:

- keyword_notification_cooldown:
  - Prevents spam by limiting how often a notification is sent for the same keyword. Default: 5 seconds.
- log_level:
  - Set Log Level. Default: INFO

---

## Enviroment Variables

These are the settings you can set via docker environment variables in either your docker compose or .env file

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| **NTFY_URL**                      | URL of the ntfy notification service.                    | _N/A_    |
| **NTFY_TOKEN**                    | Authentication token for ntfy.                           | _N/A_    |
| **NTFY_TOPIC**                    | Notification topic for ntfy.                             | Loggifly  |
| **NTFY_TAGS**                     | Ntfy [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications.                 | warning  |
| **NTFY_PRIORITY**                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| **KEYWORD_NOTIFICATION_COOLDOWN** | Cooldown period (in seconds) per container per keyword before a new message can be sent  | 5        |
| **LOG_LEVEL**                     | Log Level for Loggifly container logs.                    | INFO     |


## 🛠 Installation

### Installation via Docker Compose

1. Create a folder on your system, place the [config.yaml](config.yaml) there and edit it to fit your needs and preferences. 
2. Create a `docker-compose.yaml` file in your project and adjust it to your needs. In the volumes section you will have to specify the path to your config file.
If you want, you can uncomment the environment section to set some settings directly in your compose. (Or use an .env file)

```yaml
version: "3.8"
services:
  Loggifly:
    image: ghcr.io/clemcer/Loggifly:latest
    container_name: Loggifly
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./Loggifly/config/config.yaml:/app/config.yaml # specify the path of your condig file on the left side of the mapping
    #environment:
    #   NTFY_URL: "http://your.ntfy.server:port"
    #   NTFY_TOPIC: "your_topic"
    #   NTFY_TOKEN: "your_token"
    #   NTFY_PRIORITY: "your_priority"
    #   NTFY_TAG: "your_tag"
    #   KEYWORD_NOTIFICATION_COOLDOWN = 5
    restart: unless-stopped
```

2. Then, run the container:

```bash
docker-compose up -d
```
---

## 📃 Full example config.yaml
This is how a config file could look like. Keep in mind that this is just an example how a config.yaml could be structured and some keywords might not even make sense for some containers.

```yaml
containers:
  audiobookshelf:
    ntfy_topic: media
    ntfy_tags: "books, headphones"     
    keywords:
      - "requested download"
      - "downloaded item"
      - "user"
      - "login"
      - regex: 'download (failed|error)'    # Matches "download failed" or "download error"
        
  crowdsec:
    ntfy_topic: security
    ntfy_tags: "shield, rotating_light"  
    keywords:
      - "blocked"

  vaultwarden:
    ntfy_topic: security
    ntfy_tags: "lock, key"   
    keywords:
      - "login"
      - "incorrect"
      - "username"
      - "password"

  syncthing:
    ntfy_tags: "arrows_counterclockwise, recycle" 
    keywords:
      - "sync error"
      - "failed to connect"
    keywords_with_attachment:
      - regex: 'fatal'                     
global_keywords:
  keywords_with_attachment:
    - regex: "\\b(critical|panic)\\b"
    - "error"
    - "segfault"
    - "panic"
    - "fatal"
    - "failed login"

ntfy:
  url: "http://192.168.178.184:82"   # URL of your ntfy instance
  topic: "Loggifly"                   # Default topic for notifications (overridden by container-specific topics)
  token: "token"                     # Authentication token (if required)
  tags: "warning"

settings:
  keyword_notification_cooldown: 10
  log_level: "INFO"
```
