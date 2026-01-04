import json
import os
import logging

SETTINGS_FILE = "settings.json"
DEFAULT_SETTINGS = {
    "auto_block": True,
    "block_threshold": 0.8,
    "email_alerts": False,
    "admin_email": "balarl1301@gmail.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_password": ""
}

logger = logging.getLogger("AlertForgeSettings")

class SettingsManager:
    def __init__(self):
        self.settings = DEFAULT_SETTINGS.copy()
        self.load_settings()

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    data = json.load(f)
                    self.settings.update(data)
                logger.info("Settings loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load settings: {e}")
        else:
            self.save_settings()

    def save_settings(self):
        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump(self.settings, f, indent=4)
            logger.info("Settings saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")

    def get_all(self):
        return self.settings

    def update(self, new_settings: dict):
        self.settings.update(new_settings)
        self.save_settings()
        return self.settings

    def get(self, key, default=None):
        return self.settings.get(key, default)
