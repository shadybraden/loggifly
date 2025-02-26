
# Config Walkthrough

## 📁 Basic Structure

The `config.yaml` file is divided into four main sections:

1. **`settings`**: Global settings like cooldowns and log levels.
2. **`containers`**: Define which containers to monitor and their specific keywords.
3. **`global_keywords`**: Keywords that apply to **all** monitored containers.
4. **`notifications`ˋ`**: Configue ntfy (url, topic, token, priority and tags) or your Apprise url

---
###⚙️ `settings` section
```yaml
settings:
  log_level: INFO               # DEBUG, INFO, WARNING, ERROR
  notification_cooldown: 5      # Seconds between alerts for same keyword (per container)
  attachment_lines: 20          # Lines to include in log attachments
  multi_line_entries: true      # Detect multi-line log entries
  disable_start_message: false  # Suppress startup notification
  disable_shutdown_message: false  # Suppress shutdown notification
  disable_restart_message: false   # Suppress config reload notification
```

###🐳 `containers` section

```yaml
containers:
  exact-container-name:         # Must match docker ps/container_name
    ntfy_tags: "tag1, tag2"     # Comma-separated (optional)
    ntfy_priority: "4"          # 1-5 (optional)
    keywords:                   # Simple text matches
      - "error"
      - "critical"
```

###📭 `notiications` section

```yaml
notifications:     # At least one of the two is required. Or use env variables.
  ntfy:
    url: "http://your-ntfy-server"  
    topic: "logs"                   
    token: "ntfy-token"          
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL```
```

---

 
### 🌍 `global_keywords` Section

```yaml
global_keywords:              # These keywords are being monitored for all containers
  keywords:
    - login failed
  keywords_with_attachment:
    - critical
```

---
### 🔑 Key Features:

#### Regex Patterns (YAML Only)

```yaml
containers:
  my-container:
    keywords:
      - {regex: "\\b(?:3[0-1]|0?[0-9]|1[0-9]|2[0-9])\\d\\.log\\b"}  # Escape backslashes
```

#### Attach Logfile to notification
You can add ˋkeywords_with_attachmentˋ to either a containers section or global keywords. The number of lines the log file can be customised (See ˋsettingsˋ)

```yaml
containers:
  container-name:
    keywords:
      ...
    keywords_with_attachment:   # attach log file to notification
      - "database connection failed"
      - "out of memory"
global_keywords: 
  keywords:
  ...
  keywords_with_attachment:
    - critical
`
```

---

## Enviroment Variables

Except for container specific settings or regex patterns you can set most settings via docker environment variables in either your docker compose or .env file

| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| **NTFY_URL**                      | URL of the ntfy notification service.                    | _N/A_    |
| **NTFY_TOKEN**                    | Authentication token for ntfy.                           | _N/A_    |
| **NTFY_TOPIC**                    | Notification topic for ntfy.                             | _N/A_  |
| **NTFY_TAGS**                     | Ntfy [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications.                 | warning  |
| **NTFY_PRIORITY**                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| **NOTIFICATION_COOLDOWN**         | Cooldown period (in seconds) per container per keyword<br> before a new message can be sent  | 5        |
| **LOG_LEVEL**                     | Log Level for Loggifly container logs.                    | INFO     |
| **ATTACHMENT_LINES**              | Define the number of Log Lines in the attachment file     | False     |
| **DISABLE_RESTART**               | Disable automatic restarts when the config file is changed.| False     |
| **DISBLE_START_MESSAGE**          | Disable startup message.                                  | False     |
| **DISBLE_SHUTDOWN_MESSAGE**       | Disable shutdown message.                                 | False     |
| **DISABLE_RESTART_MESSAGE**       | Disable message on config change when programm restarts.| False     |
| **MULTI_LINE_ENTRIES**            | When enabled the programm tries to catch entries that span multiple log lines.<br>If you encounter bugs or you simply don't need it you can disable it.| False     |
| **GLOBAL_KEYWORDS**       | Global Keywords are being monitored for every container.| _N/A_  |
| **GLOBAL_KEYWORDS_WITH_ATTACHMENT**       | When these global keywords are detected<br>the last lines from the log are attached in a .log file.| _N/A_ |





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
