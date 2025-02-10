# Logsend ![Logsend Icon](icon.png)

**Logsend** is a lightweight tool for monitoring Docker container logs and sending notifications when specific keywords are detected. It supports both plain text and regular expression (regex) keywords and can attach the last 50 lines of a log file when a match is found. 🚀

---

## Features

- 🔍 **Container Log Monitoring**  
  Monitor Docker container logs in real time.

- 🏷 **Keyword Detection**  
  Trigger notifications when specific keywords (or regex patterns) are found.

- 📝 **Log Attachments**  
  Attach the last 50 lines of the log for context when a keyword match occurs.

- ⚙️ **Flexible Configuration**  
  Configure per-container keywords and global keywords via a YAML file, with additional overrides via environment variables.

- ⏱ **Notification Cooldown**  
  Prevent duplicate notifications with per-keyword and per-container cooldown settings.

---

## Installation via Docker Compose

Create a `docker-compose.yaml` file in your project with the following content:

```yaml
version: "3.8"
services:
  logsend:
    container_name: logsend
    build: .
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./logsend/config/config.yaml:/app/config.yaml
    # You can also override notification settings using environment variables:
    # environment:
    #   NTFY_URL: "http://your.ntfy.server:port"
    #   NTFY_TOPIC: "your_topic"
    #   NTFY_TOKEN: "your_token"
    #   NTFY_PRIORITY: "your_priority"
    #   NTFY_TAG: "your_tag"


| Key                                        | Description                                                                                      | Default  | Environment Variable Override |
|--------------------------------------------|--------------------------------------------------------------------------------------------------|----------|-------------------------------|
| **containers**                             | Container-specific configurations. You can specify keywords and keywords with attachments.       | _N/A_    | _N/A_                         |
| **global_keywords**                        | Keywords that apply globally to all containers.                                                  | _N/A_    | _N/A_                         |
| **notifications.ntfy.url**                 | URL of the ntfy notification service.                                                            | _None_   | `NTFY_URL`                    |
| **notifications.ntfy.topic**               | Notification topic for ntfy.                                                                     | "loggify"| `NTFY_TOPIC`                  |
| **notifications.ntfy.token**               | Authentication token for ntfy.                                                                   | _None_   | `NTFY_TOKEN`                  |
| **notifications.ntfy.priority**            | Notification priority for ntfy messages.                                                         | _None_   | `NTFY_PRIORITY`               |
| **notifications.ntfy.tag**                 | Tag(s) for ntfy notifications.                                                                   | _None_   | `NTFY_TAG`                    |
| **notifications.apprise**                  | Apprise notification settings (currently placeholders).                                          | _N/A_    | _N/A_                         |
| **settings.log-level**                     | Log level for the application.                                                                   | `INFO`   | _N/A_                         |
| **settings.keyword_notification_cooldown** | Cooldown period (in seconds) to prevent sending duplicate notifications for the same keyword.    | `5`      | _N/A_                         |
