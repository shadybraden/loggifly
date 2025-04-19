<a name="readme-top"></a>

<div align="center">
  <a href="clemcer/loggifly">
    <img src="/images/icon.png" alt="Logo" width="200" height="auto">
  </a>
</div>
<h1 align="center">LoggiFly</h1>

  <p align="center">
    <a href="https://github.com/clemcer/loggifly/issues">Report Bug</a>
    <a href="https://github.com/clemcer/loggifly/issues">Request Feature</a>
  </p>



**LoggiFly** - A Lightweight Tool that monitors Docker Container Logs for predefined keywords or regex patterns and sends Notifications.

Get instant alerts for security breaches, system errors, or custom patterns through your favorite notification channels. 🚀


**Ideal For**:
- ✅ Catching security breaches (e.g., failed logins in Vaultwarden)
- ✅ Debugging crashes with attached log context
- ✅ Restarting containers on specific errors or stopping them completely to avoid restart loops
- ✅ Monitoring custom app behaviors (e.g., when a user downloads an audiobook on your Audiobookshelf server)


<div align="center">
   <img src="/images/vault_failed_login.gif" alt="Failed Vaultwarden Login" width="auto" height="200">
</div>

---

## Content

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Quick Start](#️-quick-start)
- [Configuration Deep Dive](#-Configuration-Deep-Dive)
  - [Basic config structure](#-basic-structure)
  - [Detailed Configuration Options](#-detailed-configuration-options)
  - [Environment Variables](#-environment-variables)
- [Remote Hosts](#-remote-hosts)
  - [Labels](#labels)
  - [Remote Hosts Example](#remote-hosts-example)
  - [Socket Proxy](#-socket-proxy)
- [Tips](#-tips)
- [Support / Buy me a coffee](#support)


---

## 🚀 Features

- **🔍 Plain Text, Regex & Multi-Line Log Detection**: Catch simple keywords or complex patterns in log entries that span multiple lines.
- **🚨 Ntfy/Apprise Alerts**: Send notifications directly to Ntfy or via Apprise to 100+ different services (Slack, Discord, Telegram).
- **🔁 Trigger Stop/Restart**: A restart/stop of the monitored container can be triggered on specific critical keywords.
- **📁 Log Attachments**: Automatically include a log file to the notification for context.
- **⚡ Automatic Reload on Config Change**: The program automatically reloads the `config.yaml` when it detects that the file has been changed.

---
## 🖼 Screenshots

<div align="center">
   <img src="/images/abs_login.png" alt="Audiobookshelf Login" width="300" height="auto">
   <img src="/images/vault_failed_login.png" alt="Vaultwarden Login" width="300" height="auto">
   <img src="/images/abs_download.png" alt="Audiobookshelf Download" width="300" height="auto">
  <img src="/images/ebook2audiobook.png" alt="Ebook2Audiobook conversion finished" width="300" height="auto">

</div>

---

>[!TIP]
>For better security use a **[Docker Socket Proxy](#-socket-proxy)**.
You won't be able to trigger container stops/restarts with a proxy, but if you don't need that, consider taking a look at [this section](#-socket-proxy) before you wrap up the Quick Start install and consider using that compose file instead of the basic one.

## ⚡️ Quick start

In this quickstart only the most essential settings are covered, [here](#Configuration-Deep-Dive) is a more detailed config walkthrough.<br>

Choose your preferred setup method - simple environment variables for basic use or a YAML config for advanced control.
- Environment variables allow for a **simple** and **much quicker** setup
- With YAML you can use complex **Regex patterns**, have different keywords & other settings **per container** and set keywords that trigger a **restart/stop** of the container.

> [!Note]
In previous versions the default location for the `config.yaml` file was `/app/config.yaml`. The old path still works (so not a breaking change) but the new official path is now `/config/config.yaml`.<br>
LoggiFly will first look in `/config/config.yaml`, and fall back to `/app/config.yaml` if it's not found.<br>
When `/config` is mounted a config template will be downloaded into that directory. 

<details><summary><em>Click to expand:</em> 🐋 <strong>Basic Setup: Docker Compose (Environment Variables)</strong></summary>
Ideal for quick setup with minimal configuration

```yaml
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # This is where you would put your config.yaml file (ignore if you are only using environment variables)
      # - ./loggifly/config:/config  
    environment:
      # Choose at least one notification service
      NTFY_URL: "https://ntfy.sh"       
      NTFY_TOPIC: "your_topic"          
      # Token or Username+Password In case you need authentication
      # NTFY_TOKEN:
      # NTFY_USERNAME:
      # NTFY_PASSWORD:
      APPRISE_URL: "discord://..."      # Apprise-compatible URL
    
      CONTAINERS: "vaultwarden,audiobookshelf"        # Comma-separated list
      GLOBAL_KEYWORDS: "error,failed login,password"  # Basic keyword monitoring
      GLOBAL_KEYWORDS_WITH_ATTACHMENT: "critical"     # Attaches a log file to the notification
    restart: unless-stopped 
```
</details>


<details><summary><em>Click to expand:</em><strong> 📜 Advanced Setup: YAML Configuration</strong></summary>

Recommended for granular control, regex patterns and action_keywords. <br>

**Step 1: Docker Compose**

Use this [docker compose](/docker-compose.yaml) and edit this line:
```yaml
volumes:
  - ./loggifly/config:/config  # 👈 Replace left side of the mapping with your local path
```
If you want you can configure some of the settings or sensitive values like ntfy tokens or apprise URLs via [Environment Variables](#environment-variables).

**Step 2: Configure Your config.yaml**

If `/config` is mounted a **[template file](/config_template.yaml) will be downloaded** into that directory. You can edit the downloaded template file and rename it to `config.yaml` to use it.<br>
You can also take a look at the [Configuration-Deep-Dive](#-Configuration-Deep-Dive) for all the configuration options.<br>
Or you can edit and copy paste the following **minimal config** into a newly created `config.yaml` file in `/config`.
```yaml
# You have to configure at least one container.
containers:
  container-name:  # Exact container name
  # Configure at least one type of keywords or use global keywords
    keywords:
      - error
      - regex: (username|password).*incorrect  # Use regex patterns when you need them
    # Attach a log file to the notification 
    keywords_with_attachment:
      - warn
    # Caution advised! These keywords will trigger a restart/stop of the container
    action_keywords:
      - stop: traceback
      - restart: critical

# Optional. These keywords are being monitored for all configured containers. There is an action_cooldown (see config deep dive)
global_keywords:
  keywords:
    - failed
  keywords_with_attachment:
    - critical

notifications:     
  # Configure either Ntfy or Apprise or both
  ntfy:
    url: http://your-ntfy-server  
    topic: loggifly                   
    token: ntfy-token               # Ntfy token in case you need authentication 
    username: john                  # Ntfy Username+Password in case you need authentication 
    password: 1234                  # Ntfy Username+Password in case you need authentication 
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
```
</details><br>


**When everything is configured start the container**


```bash
docker compose up -d
```

---


## 🤿 Configuration Deep Dive

The Quick Start only covered the essential settings, here is a more detailed walktrough of all the configuration options.


### 📁 Basic Structure

The `config.yaml` file is divided into four main sections:

1. **`settings`**: Global settings like cooldowns and log levels. (_Optional since they all have default values_)
2. **`notifications`**: Configure Ntfy (_URL, Topic, Token, Priority and Tags_) and/or your Apprise URL
3. **`containers`**: Define which Containers to monitor and their specific Keywords (_plus optional settings_).
4. **`global_keywords`**: Keywords that apply to _all_ monitored Containers.


> [!IMPORTANT]
For the program to function you need to configure:
>- **at least one container**
>- **at least one notification service (Ntfy or Apprise)**
>- **at least one keyword (either set globally or per container)**
>
>  The rest is optional or has default values.


### 🔎 Detailed Configuration Options 

<details><summary><em>Click to expand:</em><strong> ⚙️ Settings </strong></summary>

```yaml
# These are the default settings
settings:          
  log_level: INFO               # DEBUG, INFO, WARNING, ERROR
  notification_cooldown: 5      # Seconds between alerts for same keyword (per container)
  action_cooldown: 300          # Cooldown period (in seconds) before the next container action can be performed. Maximum is always at least 60s.
  attachment_lines: 20          # Number of Lines to include in log attachments
  multi_line_entries: True      # Monitor and catch multi-line log entries instead of going line by line. 
  reload_config: True        # When the config file is changed the program reloads the config
  disable_start_message: False  # Suppress startup notification
  disable_shutdown_message: False  # Suppress shutdown notification
  disable_config_reload_message: False   # Suppress config reload notification
```

</details>



<details><summary><em>Click to expand:</em><strong> 📭 notifications </strong></summary>

```yaml
notifications:                       
  # At least one of the two (Ntfy/Apprise) is required.
  ntfy:
    url: http://your-ntfy-server    # Required. The URL of your Ntfy instance
    topic: loggifly.                # Required. the topic for Ntfy
    token: ntfy-token               # Ntfy token in case you need authentication 
    username: john                  # Ntfy Username+Password in case you need authentication 
    password: password              # Ntfy Username+Password in case you need authentication 
    priority: 3                     # Ntfy priority (1-5)
    tags: kite,mag                  # Ntfy tags/emojis 
  apprise:
    url: "discord://webhook-url"    # Any Apprise-compatible URL (https://github.com/caronc/apprise/wiki)
```
</details>


<details><summary><em>Click to expand:</em><strong> 🐳 containers </strong></summary>

```yaml
containers:
  container1: # leave blank if you only need global keywords

  container2: # these names must match the exact container names
    keywords:
      - keyword1
      - regex: regex-patern   # this is how to set regex patterns
    keywords_with_attachment: # attach a logfile to the notification
      - keyword2
    action_keywords: # trigger a restart/stop of the container. can not be set globally
      - restart: keyword3
      - stop: keyword4
  
  container3:
  # The next 6 settings override the global settings only for this container
    ntfy_tags: closed_lock_with_key   
    ntfy_priority: 5
    ntfy_topic: container3
    attachment_lines: 50     
    notification_cooldown: 2  
    action_cooldown: 60 
  
    keywords:
      - keyword1
    keywords_with_attachment:
      - keyword2
    action_keywords:  
      - stop: keyword3
      - restart: 
          regex: regex-pattern # this is how to set regex patterns for action_keywords
```

 </details>


<details><summary><em>Click to expand:</em><strong> 🌍 global_keywords </strong></summary>

```yaml
# This section is optional.
# These keywords are being monitored for all containers. 
global_keywords:              
  keywords:
    - error
  keywords_with_attachment:  # When one of these keywords is found a logfile is attached
    - regex: (critical|error)
```

</details>

<br>

[Here](/config_template.yaml) you can find a **config template** with all available configuration options and explaining comments. When `/config` is mounted in the volumes section of your docker compose this template file will be downloaded. <br>
[Here](/config_example.yaml) you can find an example config with some **use cases**.


### 🍀 Environment Variables

Except for `restart_keywords`, container specific settings/keywords and regex patterns you can configure most settings via **Docker environment variables**.

<details><summary><em>Click to expand:</em><strong> Environment Variables </strong></summary><br>


| Variables                         | Description                                              | Default  |
|-----------------------------------|----------------------------------------------------------|----------|
| `NTFY_URL`                      | URL of your Ntfy server instance                           | _N/A_    |
| `NTFY_TOKEN`                    | Authentication token for Ntfy in case you need authentication.      | _N/A_    |
| `NTFY_USERNAME`                 | Ntfy Username to use with the password in case you need authentication.             | _N/A_    |
| `NTFY_PASSWORD`                 | Ntfy password to use with the username in case you need authentication.             | _N/A_    |
| `NTFY_TOPIC`                    | Notification topic for Ntfy.                               | _N/A_  |
| `NTFY_TAGS`                     | [Tags/Emojis](https://docs.ntfy.sh/emojis/) for ntfy notifications. | kite,mag  |
| `NTFY_PRIORITY`                 | Notification [priority](https://docs.ntfy.sh/publish/?h=priori#message-priority) for ntfy messages.                 | 3 / default |
| `APPRISE_URL`                   | Any [Apprise-compatible URL](https://github.com/caronc/apprise/wiki)  | _N/A_    |
| `CONTAINERS`                    | A comma separated list of containers. These are added to the containers from the config.yaml (if you are using one).| _N/A_     |
| `GLOBAL_KEYWORDS`       | Keywords that will be monitored for all containers. Overrides `global_keywords.keywords` from the config.yaml.| _N/A_     |
| `GLOBAL_KEYWORDS_WITH_ATTACHMENT`| Notifications triggered by these global keywords have a logfile attached. Overrides `global_keywords.keywords_with_attachment` from the config.yaml.| _N/A_     |
| `NOTIFICATION_COOLDOWN`         | Cooldown period (in seconds) per container per keyword before a new message can be sent  | 5        | 
| `ACTION_COOLDOWN`         | Cooldown period (in seconds) before the next container action can be performed. Always at least 60s. (`action_keywords` are only configurable in YAML)  | 300        |
| `LOG_LEVEL`                     | Log Level for LoggiFly container logs.                    | INFO     |
| `MULTI_LINE_ENTRIES`            | When enabled the program tries to catch log entries that span multiple lines.<br>If you encounter bugs or you simply don't need it you can disable it.| True     |
| `ATTACHMENT_LINES`              | Define the number of Log Lines in the attachment file     | 20     |
| `RELOAD_CONFIG`               | When the config file is changed the program reloads the config | True  |
| `DISBLE_START_MESSAGE`          | Disable startup message.                                  | False     |
| `DISBLE_SHUTDOWN_MESSAGE`       | Disable shutdown message.                                 | False     |
| `DISABLE_CONFIG_RELOAD_MESSAGE`       | Disable message when the config file is reloaded.| False     |

</details>

---

## 📡 Remote Hosts

LoggiFly supports connecting to **multiple remote hosts**.<br>
Remote hosts can be configured by providing a **comma-separated list of addresses** in the `DOCKER_HOST` environment variable.<br>
To use **TLS** you have to mount `/certs` in the volumes section of your docker compose.<br>
LoggiFly expects the TLS certificates to be in `/certs/{ca,cert,key}.pem` or in case of multiple hosts `/certs/{host}/{ca,cert,key}.pem` with `{host}` being either the IP or FQDN.<br>
You can also combine remote hosts with a mounted docker socket.<br>

>[!NOTE]
When the connection to a docker host is lost, LoggiFly will try to reconnect every 60s

### Labels
When multiple hosts are set LoggiFly will use **labels** to differentiate between them both in notifications and in logging.<br>
You can set a **label** by appending it to the address with `"|"` ([_see example_](#remote-host-example)).<br>
When no label is set LoggiFly will use the **hostname** retrieved via the docker daemon. If that fails, usually because `INFO=1` has to be set when using a proxy, the labels will just be `Host-{Nr}`.<br>
If you want to set a label to the mounted docker socket you can do so by adding `unix://var/run/docker.sock|label` in the `DOCKER_HOST` environment variable (_the socket still has to be mounted_) or just set the address of a [socket proxy](#socket-proxy) with a label.

### Remote Hosts Example

In this example LoggiFly monitors container logs on the host it is running on via a mounted docker socket as well as two remote hosts set up with TLS.
One remote host will be called '_foobar_'. The host mounted via the docker socket and the other remote host have no label set and will be called whatever the hostname is.

<details><summary><em>Click to expand:</em> <strong>Remote Hosts: Docker Compose </strong></summary>

```yaml
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly 
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./loggifly/config:/config # Place your config.yaml here if you are using one
      - ./certs:/certs
      # Assuming the Docker hosts use TLS, the folder structure for the certificates should be like this:
      # /certs/
      # ├── 192.168.178.80/
      # │   ├── ca.pem
      # │   ├── cert.pem
      # │   └── key.pem
      # └── 192.168.178.81/
      #     ├── ca.pem
      #     ├── cert.pem
      #     └── key.pem
    environment:
      TZ: Europe/Berlin
      DOCKER_HOST: tcp://192.168.178.80:2376,tcp://192.168.178.81:2376|foobar
    restart: unless-stopped
```
</details>

### Socket Proxy

You can also connect via a **Docker Socket Proxy**.<br>
A Socket Proxy adds a security layer by **controlling access to the Docker daemon**, essentially letting LoggiFly only read certain info like container logs without giving it full control over the docker socket.<br>
With the linuxserver image I have had some connection and timeout problems so the recommended proxy is **[Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)**.<br>
When using the Tecnativa Proxy the log stream connection drops every ~10 minutes for whatever reason, LoggiFly simply resets the connection.<br>
Here is a sample **docker compose** file:


<details><summary><em>Click to expand:</em> <strong>Socket Proxy: Docker Compose </strong></summary>

```yaml
version: "3.8"
services:
  loggifly:
    image: ghcr.io/clemcer/loggifly:latest
    container_name: loggifly 
    volumes:
      - ./loggifly/config:/config # Place your config.yaml here if you are using one
    environment:
      TZ: Europe/Berlin
      DOCKER_HOST: tcp://socket-proxy:2375
    depends_on:
      - socket-proxy
    restart: unless-stopped
    
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: docker-socket-proxy
    environment:
      - CONTAINERS=1  
      - POST=0        
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro  
    restart: unless-stopped

```
</details>


>[!Note]
`action_keywords` don't work when using a socket proxy.
<br>


## 💡 Tips

1. Ensure containers names **exactly match** your Docker **container names**. 
    - Find out your containers names: ```docker ps --format "{{.Names}}" ```
    - 💡 Pro Tip: Define the `container_name:` in your compose files.
2. **`action_keywords`** can not be set via environment variables, they can only be set per container in the `config.yaml`. The `action_cooldown` is always at least 60s long and defaults to 300s
3. **Test Regex Patterns**: Validate patterns at [regex101.com](https://regex101.com) before adding them to your config.
4. **Troubleshooting Multi-Line Log Entries**. If LoggiFly only catches single lines from log entries that span over multiple lines:
    - Wait for Patterns: LoggiFly needs to process a few lines in order to detect the pattern the log entries start with (e.g. timestamps/log level)
    - Unrecognized Patterns: If issues persist, open an issue and share the affected log samples

---


## Support

If you find LoggiFly useful, drop a ⭐️ on the repo

<p>
    <a href="https://www.buymeacoffee.com/clemcer" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>
</p>


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=clemcer/loggifly&type=Date)](https://www.star-history.com/#clemcer/loggifly&Date)

## License
[MIT](https://github.com/clemcer/LoggiFly/blob/main/LICENSE)
