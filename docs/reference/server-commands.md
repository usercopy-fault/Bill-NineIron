# Server Commands Reference
## File servers · Web servers · Listeners · Tunnels

---

## goshs (Go Simple HTTP Server)

### Basic
```bash
goshs                                   # serve CWD on :8000
goshs -p 9000                           # custom port
goshs -d /path/to/dir                   # custom root directory
goshs -i 0.0.0.0                        # all interfaces (default)
goshs -i 127.0.0.1                      # loopback only
goshs -ro                               # read-only (no upload)
goshs -uo                               # upload-only (no download)
goshs -si                               # silent — no directory listing (direct file access only)
goshs -V                                # verbose logging
```

### TLS
```bash
goshs -s -ss                            # HTTPS with self-signed cert
goshs -s -sk key.pem -sc cert.pem       # HTTPS with custom cert
goshs -s -p12 server.p12               # HTTPS with PKCS12
goshs -s -sl -sle you@mail.com -sld example.com   # Let's Encrypt
```

### Auth
```bash
goshs -b 'user:password'                # HTTP Basic Auth
goshs -b ':password'                    # Basic Auth, empty username
goshs -b 'user:$2a$14$...'             # bcrypt hash password
goshs -H 'mypassword'                   # generate bcrypt hash
goshs -ca ca.pem                        # certificate-based auth
```

### Advanced
```bash
goshs -w -wp 8001                       # + WebDAV on :8001
goshs -sftp -sp 2022                    # + SFTP server on :2022
goshs -c -b 'admin:pass' -s -ss        # CLI mode (needs auth + TLS)
goshs -ipw 192.168.1.0/24,10.0.0.5     # IP whitelist
goshs -W -Wu https://hooks.slack.com/... -Wp Slack   # Webhook on events
goshs -o -V                             # log to file + verbose
goshs -e                                # show embedded/hidden files in UI
goshs -nd                               # disable delete
goshs -nc                               # disable clipboard sharing
goshs -m                                # disable mDNS registration
goshs -I                                # invisible mode (no UI banner)
goshs --update                          # auto-update binary
goshs -P                                # print sample YAML config
goshs -C /path/to/config.yaml           # use config file
```

### Bug bounty combos
```bash
# Serve payloads over HTTPS (bypass mixed-content blocks)
goshs -d ~/bb/payloads -p 443 -s -ss

# Receive exfil uploads, read-only everything else
goshs -d /tmp/exfil -uf /tmp/exfil -uo -p 8888

# Authenticated file drop with webhook notification
goshs -b ':secret' -W -Wu https://discord.com/api/webhooks/XXX/YYY -Wp Discord

# Serve postMessage probe on Tailscale IP only
goshs -d /tmp/goshs-dyson -i 100.64.0.10 -p 8765 -si

# SFTP + HTTP combined drop server
goshs -sftp -sp 2022 -b 'bb:pass' -s -ss
```

---

## Python HTTP Servers

### Basic
```bash
python3 -m http.server                  # serve CWD on :8000
python3 -m http.server 9000             # custom port
python3 -m http.server 8080 --bind 127.0.0.1   # bind to loopback
python3 -m http.server --directory /path/to/dir 8080

# Python 2 (legacy)
python2 -m SimpleHTTPServer 8000
```

### CGI server (execute scripts)
```bash
python3 -m http.server --cgi 8080
# place scripts in cgi-bin/ directory
```

### Custom one-liners
```python
# Upload-capable server
python3 -c "
import http.server, socketserver, os
PORT = 8080
class H(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        fname = self.path.lstrip('/')
        open(fname, 'wb').write(data)
        self.send_response(200); self.end_headers()
        self.wfile.write(b'saved')
with socketserver.TCPServer(('', PORT), H) as s:
    s.serve_forever()
"
```

```python
# CORS-enabled server (for cross-origin postMessage testing)
python3 -c "
import http.server
class CORSHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Headers','*')
        self.send_header('Access-Control-Allow-Methods','*')
        super().end_headers()
    def log_message(self, fmt, *args):
        print(self.address_string(), '-', fmt % args)
http.server.HTTPServer(('', 8080), CORSHandler).serve_forever()
"
```

```python
# TLS (HTTPS) server — self-signed
python3 -c "
import http.server, ssl
httpd = http.server.HTTPServer(('0.0.0.0', 4443), http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./cert.pem', keyfile='./key.pem', server_side=True)
httpd.serve_forever()
"
# Generate cert first:
# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'
```

```bash
# uvicorn async (if installed)
uvicorn myapp:app --host 0.0.0.0 --port 8080 --reload

# gunicorn
gunicorn -b 0.0.0.0:8080 -w 4 myapp:app
```

---

## Netcat / Ncat Listeners

### Basic TCP listeners
```bash
nc -lvnp 4444                           # basic listener
nc -lvnp 4444 -e /bin/bash              # bind shell (GNU nc)
ncat -lvnp 4444                         # ncat (nmap)
ncat --ssl -lvnp 4444                   # TLS listener
ncat -lvnp 4444 -k                      # keep-open (accept multiple)
```

### File transfer via netcat
```bash
# Receive file
nc -lvnp 9001 > received_file

# Send file
nc TARGET_IP 9001 < file_to_send

# Send directory (tar pipe)
tar czf - /path/to/dir | nc TARGET_IP 9001

# Receive directory
nc -lvnp 9001 | tar xzf -
```

### HTTP response via netcat
```bash
{ echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(document.domain)</script>"; } | nc -lvnp 8080
```

### Exfil listener (log incoming requests)
```bash
ncat -lvnp 8080 -k --output /tmp/exfil.log
```

---

## Socat

### TCP relay
```bash
socat TCP-LISTEN:8080,fork TCP:TARGET:80             # TCP proxy
socat TCP-LISTEN:8080,reuseaddr,fork -               # echo server
socat TCP-LISTEN:443,fork,reuseaddr OPENSSL:TARGET:443,verify=0   # TLS relay
```

### File server
```bash
socat TCP-LISTEN:8080,reuseaddr,fork OPEN:file.txt,rdonly
```

### TLS listener
```bash
socat OPENSSL-LISTEN:4433,cert=server.pem,verify=0,fork -
```

---

## Nginx (one-shot / pentest configs)

### Minimal static file server
```bash
# /tmp/nginx-bb.conf
cat > /tmp/nginx-bb.conf <<'EOF'
events {}
http {
    include /etc/nginx/mime.types;
    server {
        listen 8080;
        root /tmp/www;
        autoindex on;
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Headers *;
    }
}
EOF
nginx -c /tmp/nginx-bb.conf
nginx -c /tmp/nginx-bb.conf -s stop
```

### Reverse proxy for pentest
```nginx
location /api/ {
    proxy_pass http://target.internal/;
    proxy_set_header Host target.internal;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

---

## Ruby / PHP / Node Quick Servers

```bash

### bore (self-hosted)
```bash
bore local 8080 --to bore.pub
bore local 8080 --to bore.pub --port 2333
```

### SSH remote port forward
```bash
# Expose localhost:8080 as attacker.com:9090
ssh -R 9090:localhost:8080 user@attacker.com -N
# In ~/.ssh/config on server: GatewayPorts yes
```

---

## Interactsh (OOB interaction server — ProjectDiscovery)

```bash
# Start interactsh server (public)
interactsh-client                       # uses interact.sh

# Custom server
interactsh-server -domain example.com -hostmaster admin@example.com

# SSRF / blind XSS canary
# In payloads use: YOUR_ID.oast.pro
# or: YOUR_ID.interact.sh

# View correlations
interactsh-client -id YOUR_ID

# With caido hook
interactsh-client -server https://interact.sh -json
```

---

## Impacket SMB / FTP / HTTP servers

```bash
# SMB server (NTLMv2 capture)
impacket-smbserver share /tmp/share -smb2support
impacket-smbserver share /tmp/share -smb2support -username bb -password pass

# FTP server
impacket-ftpserver -p 21 /tmp/ftp

# HTTP server
impacket-httpserver -port 8080 /tmp/www
```

---

## WebDAV servers

```bash
# wsgidav (Python)
pip install wsgidav cheroot
wsgidav --host 0.0.0.0 --port 8080 --root /tmp/webdav --auth anonymous

# goshs WebDAV
goshs -w -wp 8001

# Caddy
caddy file-server --root /tmp/www --listen :8080 --browse
```

---

## TLS cert generation (quick)

```bash
# Self-signed cert (1 year)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj '/CN=localhost'

# With SAN (required by modern browsers)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj '/CN=localhost' \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

# View cert
openssl x509 -in cert.pem -noout -text | grep -A2 'Subject\|SAN\|Valid'

# mkcert (trusted in system store)
mkcert -install
mkcert localhost 127.0.0.1 100.64.0.10
```

---

## CORS / postMessage probe servers

### Minimal CORS HTML file server
```bash
# Python CORS server (see above)
# Or with goshs (CORS headers not built-in, use nginx upstream or add header in page)

# Quick CORS check from CLI
curl -H "Origin: https://evil.com" -I https://target.com/api/endpoint | grep -i access-control
```

### postMessage test harness
```bash
# Served by current goshs instance:
# http://127.0.0.1:8765/index.html
# http://100.64.0.10:8765/index.html   (Tailscale — reachable from phone)
# http://192.168.50.10:8765/index.html   (LAN)
```

---

## Quick reference table

| Server | Command | Use case |
|--------|---------|----------|
| goshs | `goshs -p 8080 -si` | Fast BB file hosting |
| python | `python3 -m http.server` | Zero-dep static files |
| php | `php -S 0.0.0.0:8080` | PHP test pages |
| ruby | `ruby -run -e httpd .` | One-liner static |
| node | `npx http-server --cors` | JS/CORS testing |
| nc | `nc -lvnp 4444` | Reverse shell / exfil listener |
| socat | `socat TCP-LISTEN:80,fork -` | TCP proxy / relay |
| ngrok | `ngrok http 8080` | Public HTTPS URL |
| cloudflared | `cloudflared tunnel --url http://localhost:8080` | CF-signed public URL |
| impacket-smb | `impacket-smbserver share .` | NTLM capture |
| interactsh | `interactsh-client` | OOB interaction (SSRF/blind XSS) |
| goshs+WebDAV | `goshs -w` | WebDAV uploads |
| goshs+SFTP | `goshs -sftp` | SFTP uploads |
| goshs+TLS | `goshs -s -ss` | HTTPS self-signed |
