# Phone Twins (mkcert HTTPS)

This project serves a full-screen Three.js scene and streams:
- GPS
- device orientation
- local time

to everyone connected via **WebSockets**.

## Why mkcert?
Mobile browsers (especially iOS Safari) require a **trusted HTTPS** context for motion + geolocation APIs.

## Quick start (HTTPS, recommended)
1) Install Node + npm
2) Install mkcert (and run `mkcert -install` at least once on the host machine)

Then:

```bash
npm install
python server.py
```

It will:
- generate `./certs/cert.pem` + `./certs/key.pem` using mkcert (if they don't exist)
- start the Node websocket server on **https://<LAN_IP>:8443** (default)
- print LAN URLs you can tap on your phone

### Change port
```bash
HTTPS_PORT=443 python server.py
# or:
python server.py --https-port 443
```

> On macOS/Linux, ports <1024 require sudo.

## If your phone says the certificate is not trusted
mkcert installs a trusted local CA on your **computer**, not automatically on your phone.

To trust it on your phone:
- Run: `mkcert -CAROOT`
- Copy the `rootCA.pem` to the phone and install it as a profile/certificate.
  - iOS: after installing, enable full trust in Settings.
  - Android: install as a user CA (behavior varies by vendor/OS).

(If you skip this, Safari may refuse sensor permissions.)

## HTTP (fallback)
```bash
npm install
node server.js
```
Open: `http://<LAN_IP>:8080`

This may work on some Android setups but is not reliable for iOS sensor permissions.
