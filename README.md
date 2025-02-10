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
