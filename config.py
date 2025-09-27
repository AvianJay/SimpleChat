import os
import json

version = "0.0.1"
config_version = 1
config_path = 'config.json'
hash = "unknown"
if hash == "unknown":
    try:
        hash = os.popen("git rev-parse --short HEAD").read().strip()
    except Exception as e:
        print("Failed to get git hash:", str(e))

default_config = {
    "config_version": config_version,
    "host": "0.0.0.0",
    "port": 5000,
    "ssl": False,
    "ssl_cert": "",
    "ssl_key": "",
    "debug": False,
    "database_path": "app.db",
    "config_version": config_version
}
_config = None

try:
    if os.path.exists(config_path):
        _config = json.load(open(config_path, "r"))
        # Todo: verify
        if not isinstance(_config, dict):
            print("Config file is not a valid JSON object, \
                resetting to default config.")
            _config = default_config.copy()
        for key in _config.keys():
            if not isinstance(_config[key], type(default_config[key])):
                print(f"Config key '{key}' has an invalid type, \
                      resetting to default value.")
                _config[key] = default_config[key]
        if "config_version" not in _config:
            print("Config file does not have 'config_version', \
                resetting to default config.")
            _config = default_config.copy()
    else:
        _config = default_config.copy()
        json.dump(_config, open(config_path, "w"), indent=4)
except ValueError:
    _config = default_config.copy()
    json.dump(_config, open(config_path, "w"), indent=4)

if _config.get("config_version", 0) < config_version:
    print("Updating config file from version",
          _config.get("config_version", 0),
          "to version",
          config_version
          )
    for k in default_config.keys():
        if _config.get(k) is None:
            _config[k] = default_config[k]
    _config["config_version"] = config_version
    print("Saving...")
    json.dump(_config, open(config_path, "w"), indent=4)
    print("Done.")

def config(key, value=None, mode="r"):
    if mode == "r":
        return _config.get(key)
    elif mode == "w":
        _config[key] = value
        json.dump(_config, open(config_path, "w"), indent=4)
        return True
    else:
        raise ValueError(f"Invalid mode: {mode}")
