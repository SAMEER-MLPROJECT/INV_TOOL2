# AttackGraph Lens edge app for Arduino App Lab (Linux side).
# Copy ../../agent.py next to this file and create edge_config.json next to it:
#   {"AGL_URL": "https://<your-app>", "AGL_DEVICE_ID": "dev_...", "AGL_DEVICE_SECRET": "<64 hex>", "AGL_ALLOW_USB": "046d:0825"}
import os
import threading

import agent
from arduino.app_utils import App

args = [] if os.path.exists("/var/log/auth.log") else ["--no-logins"]
threading.Thread(target=agent.main, args=(args,), name="agl-edge", daemon=True).start()
App.run()
