#!/bin/sh

CONFIG_DIR=/config
CONFIG_TEMPLATE=$CONFIG_DIR/config_template.yaml
CONFIG_FILE=$CONFIG_DIR/config.yaml
CONFIG_URL=https://raw.githubusercontent.com/clemcer/loggifly/refs/heads/main/config_template.yaml

if [ -d "$CONFIG_DIR" ]; then
    #echo "/config exists."
    if [ ! -f "$CONFIG_TEMPLATE" ] && [ ! -f "$CONFIG_FILE" ]; then
        echo "loading config.yaml template..."
        python3 -c "import urllib.request; urllib.request.urlretrieve('$CONFIG_URL', '$CONFIG_TEMPLATE')"
    # else
    #     echo "config.yaml or config template already exists."
    fi
else
    echo "/config does not exist, skipping config template download."
fi

exec python /app/app.py