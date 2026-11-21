# Arduino UNO Q edge sensor

The UNO Q is a monitored machine in the server room. It reports what happens to it physically, as signed and
hash-chained evidence, into the same graph as the digital logs.

| Event | Where it comes from | Default severity |
|---|---|---|
| `usb_connect` / `usb_disconnect` | `/sys/bus/usb/devices` (polled every second) | `info` if on the allow-list, else `medium` / `low` |
| `ssh_login`, `console_login`, `login_failed` | systemd journal (`sshd`, `login`) or `/var/log/auth.log` | `low` / `medium` |
| `tamper_test` | you, on purpose: `python3 agent.py --self-test` | `medium` |
| `integrity_alert` | the **server**, when an envelope arrives after a sequence gap or with a broken hash chain | `high` |
| heartbeat (empty envelope every 15 s) | agent | the reply carries the organisation's top incident priority for the LED matrix |

None of these is treated as proof of an attack. They become evidence with a source, a time and a confidence level.

## Hardware

* Arduino UNO Q, powered through a **powered USB-C hub** (the 15.3 W supply into the hub's power input).
* Logitech C270 webcam into the hub. It is on the allow-list (`046d:0825`), so plugging it in is recorded as expected.
* Any other USB stick or keyboard you plug into the hub is reported as **not on the allow-list**.

App Lab reaches the board over Wi-Fi once the hub occupies the USB-C port.

## 1. Register the device

In AttackGraph Lens: **Settings & Data → Edge devices → Register** (analyst role). Copy the device id and secret; the
secret is shown once. The location is stored on the server, so the device cannot claim to be somewhere else.

For hosts that wipe their disk on restart (Render free tier), provision the device from the environment instead:

```
AGL_EDGE_DEVICES=[{"id":"dev_unoq01","name":"UNOQ-RACK-01","location":"Server room A","secret":"<64 hex>"}]
```

Generate a secret with `python3 -c "import secrets; print(secrets.token_hex(32))"`.

## 2a. Run on the board's Linux side (USB + logins)

```bash
scp agent.py arduino@<uno-q-ip>:~/agl/agent.py
ssh arduino@<uno-q-ip>
cd ~/agl
cat > edge_config.json <<'JSON'
{"AGL_URL": "https://<your-app>", "AGL_DEVICE_ID": "dev_...", "AGL_DEVICE_SECRET": "<64 hex>", "AGL_ALLOW_USB": "046d:0825"}
JSON
python3 agent.py --self-test      # one controlled tamper_test event; expect "self-test accepted"
sudo python3 agent.py             # sudo so it can read the journal; Ctrl-C to stop
```

Optional service: `agl-edge.service` in this folder.

## 2b. Run as an App Lab app (USB + LED matrix)

Create a new app in Arduino App Lab and paste:

* `applab/python/main.py` as `python/main.py`, plus `agent.py` and `edge_config.json` next to it;
* `applab/sketch/sketch.ino` as the sketch. It uses `Arduino_LED_Matrix` and `Arduino_RouterBridge`; add them through
  "Add sketch library" if App Lab asks. If your App Lab version's examples call `Bridge.update()` in `loop()`, add it.

The LED matrix shows the organisation's top incident priority: one dot = Low, rising bars = Moderate/High, full
blinking bars = Critical. Login monitoring may be unavailable inside the App Lab container; the agent says so.

## 3. Check it worked

* Agent log: `usb_connect: 0781:5567 Cruzer Blade (NOT on the allow-list)`.
* **Evidence** page, source `edge_physical`: the event, its raw record with `signature: verified`, envelope sequence and hash.
* **Infrastructure** page: the event under "Device and infrastructure events", marked "same room as incident assets"
  when the room holds servers from the incident.
* **Attack Graph**: `device:usb:... → PLUGGED_INTO → host:UNOQ-RACK-01`, and the host `LOCATED_IN` its room.

## Verified so far

* Server side: signature, replay, clock, sequence-gap, hash-chain, location-spoofing and organisation-isolation tests
  pass (`backend/tests/test_edge.py`).
* The real `agent.py` was run against a running server with a simulated `/sys/bus/usb/devices` tree: plug and unplug
  were reported, verified and turned into a `PLUGGED_INTO` relationship.
* **Not yet verified on the physical UNO Q**: journal access, the App Lab container's view of `/sys`, and the LED sketch.
  Test these at the venue before the demo.
