# Bridge — NetSuite ↔ Bank SFTP Middleware

> Secure, self-hosted middleware running on OCI (Oracle Cloud Infrastructure) at **rove.banksuite.vantheon.com** that automatically moves payment files between NetSuite and bank SFTP servers, with a web dashboard and full audit trail.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [How It Works — Plain English](#2-how-it-works--plain-english)
3. [Technologies Used](#3-technologies-used)
4. [Folder Structure](#4-folder-structure)
5. [Prerequisites](#5-prerequisites)
6. [Local Setup (Development)](#6-local-setup-development)
7. [Environment Variables](#7-environment-variables)
8. [Bank Configuration](#8-bank-configuration)
9. [Production Deployment on OCI](#9-production-deployment-on-oci)
10. [First Login and User Setup](#10-first-login-and-user-setup)
11. [Features and Functionality](#11-features-and-functionality)
12. [API Reference](#12-api-reference)
13. [Architecture Deep Dive](#13-architecture-deep-dive)
14. [Data Flow Walkthrough](#14-data-flow-walkthrough)
15. [PGP Encryption Support](#15-pgp-encryption-support)
16. [Troubleshooting — Logs, Database, and Diagnostics](#16-troubleshooting--logs-database-and-diagnostics)
17. [Security Notes](#17-security-notes)
18. [Best Practices and Operational Notes](#18-best-practices-and-operational-notes)
19. [Maintenance Reference](#19-maintenance-reference)

---

## 1. Project Overview

### What is Bridge?

Bridge is a **file-transfer relay server**. It sits between two systems that need to exchange financial files:

- **NetSuite** — a cloud ERP system that generates payment instruction files (CSV) and expects bank statement files back
- **Bank SFTP servers** — secure file servers run by banks that receive payment files and return account statements

Bridge watches both sides on a 30-second schedule, picks up new files, and delivers them to the other end — automatically, without manual intervention.

### The problem it solves

NetSuite can place payment files on its own SFTP server, but it cannot push directly to a bank's proprietary SFTP, and banks cannot pull from NetSuite. Bridge is the relay that:

- Polls NetSuite's SFTP for new payment CSV files and forwards them to the correct bank
- Polls each bank's SFTP for statement files (MT940, BAI2, etc.) and delivers them back to NetSuite
- Prevents duplicate deliveries using SHA-256 content hashing and database locking
- Archives every file and maintains a full, queryable audit trail in PostgreSQL
- Exposes a secure web dashboard for operators to monitor transfers, retry failures, and manage users

### Production server

| Item | Value |
|---|---|
| Platform | Oracle Cloud Infrastructure (OCI) VM — Ubuntu 24.04 |
| Dashboard URL | `https://rove.banksuite.vantheon.com` |
| App process | systemd service `bridge` |
| App runs as | OS user `bridge`, working directory `/opt/bridge` |
| App port (internal) | 8000 (bound to `127.0.0.1` — not exposed directly) |
| Reverse proxy | nginx on ports 80/443 |
| TLS | Let's Encrypt certificate, auto-renewed |

---

## 2. How It Works — Plain English

Think of Bridge like a secure postal relay:

1. **NetSuite drops a payment file in its outbox** — a folder on its SFTP server
2. **Bridge checks that outbox every 30 seconds**, downloads any new files, and records them in a database
3. **Bridge checks: "Have I seen this exact file before?"** — if yes, it discards it as a duplicate; if no, it continues
4. **Bridge uploads the file to the correct bank's SFTP server**
5. **Bridge saves a copy** in its local archive and writes a record to the database
6. **The bank drops a statement in its own outbox** — Bridge picks that up and delivers it back to NetSuite

All events are logged in PostgreSQL. The web dashboard at `https://rove.banksuite.vantheon.com` shows every transfer with its status, logs, and hashes. Operators can manually retry failures or upload files directly.

> **SFTP** = SSH File Transfer Protocol. A secure way to transfer files over the internet, encrypted using SSH.
>
> **MT940 / BAI2 / CSV** = File format standards used in banking for statements and payment instructions.
>
> **PostgreSQL** = A database — a program that stores data in tables, like a powerful spreadsheet that the application can query.

---

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| **Python 3.11+** | Core language |
| **FastAPI** | Web framework — serves the dashboard and API |
| **Uvicorn** | ASGI web server — runs the FastAPI app |
| **asyncssh** | Async SFTP client — connects to NetSuite and bank SFTP servers |
| **asyncio** | Python concurrency — runs the poll loop and web server simultaneously |
| **PostgreSQL** | Database — stores transfers, logs, and user accounts |
| **psycopg2** | Python driver to talk to PostgreSQL |
| **bcrypt** | Hashes passwords securely — never stored as plain text |
| **pyotp** | Generates and verifies TOTP codes (Google Authenticator / Authy) |
| **qrcode** | Creates the QR code shown during MFA setup |
| **Jinja2** | HTML templating for dashboard pages |
| **python-gnupg** | PGP file encryption/decryption (optional, per bank) |
| **nginx** | Reverse proxy — handles HTTPS/TLS, sits in front of the app |
| **systemd** | Keeps the app running, restarts it on failure |
| **Let's Encrypt / certbot** | Free TLS certificate, auto-renewed |
| **fail2ban** | Bans IPs that repeatedly fail login |

---

## 4. Folder Structure

### Source files (deployed to `/opt/bridge/`)

```
bridge/
├── bridge.py          ← Entire application — all logic is in this one file
├── requirements.txt   ← Python package list
└── templates/
    ├── dashboard.html ← Operator web UI
    ├── login.html     ← Login page
    ├── mfa_setup.html ← MFA enrollment (shown once on first login)
    └── mfa_verify.html← MFA code entry (shown on every subsequent login)
```

### Runtime data directories (auto-created under `/opt/bridge/`)

```
data/
├── staging/               ← Files being downloaded/processed right now (temporary)
├── upload_staging/        ← Files injected via the dashboard upload form (temporary)
├── processed/             ← Permanent archive of every successfully transferred file
│   └── YYYY-MM-DD/
│       └── <bank_id>/
│           └── [<account_id>/]
│               └── outbound/ or inbound/
│                   └── filename.csv
├── error/                 ← Files that were manually abandoned by an operator
├── netsuite/              ← NetSuite mirror, ACK receipts, and NACK records
│   └── <bank_id>/
│       └── [<account_id>/]
│           ├── outbound/  ← (NS_SFTP_SERVER_MODE only) NetSuite drops files here
│           ├── inbound/   ← (NS_SFTP_SERVER_MODE only) Files ready to go to NetSuite
│           ├── ACK/       ← Copies of files successfully delivered to the bank
│           └── NACK/      ← Copies of files that failed or were bank-rejected
├── banks/                 ← Only used in local/test mode (simulates bank SFTP)
│   └── <bank_id>/
│       ├── outbound/
│       └── inbound/
├── banks_config.json      ← Runtime bank configuration file (see Section 8)
└── gnupg/                 ← PGP key storage — chmod 700 (only if PGP is used)
```

> **ACK** = Acknowledgement — a copy of a file that was successfully delivered.
> **NACK** = Negative Acknowledgement — a copy of a file that failed delivery, or a bank rejection response.

---

## 5. Prerequisites

### For local development / testing

- Python 3.11 or higher
- PostgreSQL 14 or higher (running locally)

### For production (already set up on the OCI instance)

- Ubuntu 24.04 server with reserved public IP
- Domain `rove.banksuite.vantheon.com` mapped via DNS A record
- Python 3.11+, PostgreSQL, nginx, certbot, fail2ban
- Ports 22, 80, 443 open in OCI Security List and ufw

---

## 6. Local Setup (Development)

Use this section to run Bridge on your own machine for testing. In local mode, **no SFTP connections are made** — files are exchanged between local folders, so you do not need live NetSuite or bank credentials.

### Step 1 — Enter the project directory

```bash
cd bridge
```

### Step 2 — Create and activate a Python virtual environment

> A **virtual environment** keeps the project's packages isolated from your system Python so there are no version conflicts.

```bash
python3 -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

Your terminal prompt will show `(venv)` when active.

### Step 3 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4 — Set up PostgreSQL

```bash
# Create the database user and database (run once)
sudo -u postgres psql <<EOF
CREATE USER bridge WITH PASSWORD 'choose_a_strong_password';
CREATE DATABASE bridge OWNER bridge;
REVOKE ALL ON DATABASE bridge FROM PUBLIC;
EOF
```

Bridge creates all tables automatically on first start. No SQL migrations to run manually.

### Step 5 — Create a `.env` file

Create a file named `.env` in the `bridge/` directory:

```env
# ── Mode ─────────────────────────────────────────────────────
# 'local' = no SFTP connections, uses local folders (safe for development)
# 'sftp'  = connects to real SFTP servers (production)
BRIDGE_MODE=local

# ── Web server ────────────────────────────────────────────────
BIND_HOST=127.0.0.1
SESSION_HTTPS_ONLY=false

# Generate a random secret (run once, then paste result here):
# python3 -c "import secrets; print(secrets.token_hex(32))"
SESSION_SECRET=replace_with_a_long_random_string

# ── Admin login ───────────────────────────────────────────────
ADMIN_USER=admin
ADMIN_PASS=change_this_password

# ── Database ──────────────────────────────────────────────────
PG_HOST=localhost
PG_PORT=5432
PG_DB=bridge
PG_USER=bridge
PG_PASS=choose_a_strong_password

# ── NetSuite SFTP (only needed when BRIDGE_MODE=sftp) ─────────
NS_HOST=sftp.your-netsuite.com
NS_PORT=22
NS_USER=ns_sftp_user
NS_PASS=ns_sftp_password
# OR use a key file: NS_KEY=/path/to/netsuite_rsa
NS_OUTBOUND_DIR=/outbound
NS_INBOUND_DIR=/inbound

# ── Banks ─────────────────────────────────────────────────────
# For local testing, use a placeholder bank:
BANKS_JSON=[{"id":"testbank","host":"","port":22,"user":"","pass":"","inbound_dir":"/incoming","outbound_dir":"/outgoing","accounts":[]}]

# ── Tuning ────────────────────────────────────────────────────
POLL_SECONDS=30
MAX_FILES_PER_CYCLE=50
MAX_UPLOAD_BYTES=20971520
MAX_CONCURRENT_SFTP=2
STAGING_MAX_AGE_HOURS=48
```

### Step 6 — Load environment variables and start

```bash
# Export variables from .env
export $(grep -v '^#' .env | grep -v '^$' | xargs)

# Start the server
python bridge.py
```

Expected startup output:

```
2026-05-12 10:00:00  INFO     PostgreSQL connected (bridge@localhost/bridge)
2026-05-12 10:00:00  INFO     Database ready
2026-05-12 10:00:00  WARNING  Default admin 'admin' created — change ADMIN_PASS env var!
2026-05-12 10:00:01  INFO     Poller started (every 30s, mode=local, ns=local, banks=1, segregation=True)
```

Open `http://127.0.0.1:8000` — you should see the login page.

### Step 7 — Generate test files (optional)

```bash
python bridge.py --test
```

This creates synthetic files in `data/netsuite/testbank/outbound/` and `data/banks/testbank/outbound/`. Within 30 seconds the poller will pick them up. Watch them appear in the dashboard.

---

## 7. Environment Variables

### Complete reference

| Variable | Default | Description |
|---|---|---|
| `BRIDGE_MODE` | `local` | **`local`** for testing (no SFTP), **`sftp`** for production. Note: the variable name is `BRIDGE_MODE`, not `MODE`. |
| `BIND_HOST` | `0.0.0.0` | Set to `127.0.0.1` when running behind nginx (always do this in production) |
| `SESSION_SECRET` | random | Secret key for signing session cookies. If not set, every server restart logs all users out. |
| `SESSION_HTTPS_ONLY` | `false` | Set to `true` in production — prevents session cookies over plain HTTP |
| `ADMIN_USER` | `admin` | Username for the bootstrapped admin account (only created when the users table is empty) |
| `ADMIN_PASS` | `admin` | Password for the bootstrapped admin — **always change this** |
| `PG_HOST` | `localhost` | PostgreSQL host |
| `PG_PORT` | `5432` | PostgreSQL port |
| `PG_DB` | `bridge` | Database name |
| `PG_USER` | `bridge` | Database user |
| `PG_PASS` | `bridge` | Database password |
| `NS_HOST` | _(empty)_ | NetSuite SFTP hostname |
| `NS_PORT` | `22` | NetSuite SFTP port |
| `NS_USER` | _(empty)_ | NetSuite SFTP username |
| `NS_PASS` | _(empty)_ | NetSuite SFTP password (use `NS_KEY` instead in production) |
| `NS_KEY` | _(empty)_ | Absolute path to SSH private key for NetSuite SFTP |
| `NS_OUTBOUND_DIR` | `/outbound` | Directory Bridge polls on NetSuite SFTP for payment files |
| `NS_INBOUND_DIR` | `/inbound` | Directory Bridge writes bank statements to on NetSuite SFTP |
| `NS_SFTP_SERVER_MODE` | `false` | When `true`, Bridge reads from local `data/netsuite/` dirs instead of dialling NS |
| `SFTP_FOLDER_SEGREGATION` | `true` | When `true`, appends `/<bank_id>[/<account_id>]` to all NS SFTP paths |
| `SFTP_KNOWN_HOSTS` | _(empty)_ | Path to known_hosts file. Required in production to prevent MITM attacks. |
| `SFTP_TIMEOUT` | `30` | Seconds before an SFTP operation times out |
| `BANKS_JSON` | _(empty)_ | JSON array of bank configurations (see Section 8) |
| `POLL_SECONDS` | `30` | How often Bridge polls for new files |
| `MAX_FILES_PER_CYCLE` | `50` | Max files processed per poll cycle |
| `MAX_UPLOAD_BYTES` | `20971520` | Max manual upload file size (default 20 MB) |
| `MAX_CONCURRENT_SFTP` | `2` | Max simultaneous open SFTP connections |
| `STAGING_MAX_AGE_HOURS` | `48` | Hours before orphaned staging files are cleaned up |

> **Important:** There is no SMTP / email alert configuration. Email alerting is not used in this deployment.

---

## 8. Bank Configuration

> **Banks cannot be added or edited through the dashboard UI.** Bank configuration is managed entirely through the environment variable `BANKS_JSON` or by editing the `data/banks_config.json` file directly on the server.

### How the bank config is loaded

Bridge checks these sources in order, and uses the **first one that has valid data**:

```
1. /opt/bridge/data/banks_config.json   ← highest priority (if this file exists)
2. BANKS_JSON environment variable       ← second priority
3. BANK_* individual env vars            ← legacy fallback (single bank only)
```

If `data/banks_config.json` exists, it always wins — even if `BANKS_JSON` is set in `.env`. Check this file first when debugging unexpected bank behavior.

### Bank JSON format

Each bank is one object in a JSON array:

```json
[
  {
    "id": "hsbc",
    "name": "HSBC",
    "host": "sftp.hsbc.com",
    "port": 22,
    "user": "your_sftp_username",
    "pass": "your_sftp_password",
    "key": "/opt/bridge/keys/hsbc_rsa",
    "inbound_dir": "/incoming",
    "outbound_dir": "/outgoing",
    "accounts": [
      {
        "id": "acc001",
        "inbound_dir": "/incoming/acc001",
        "outbound_dir": "/outgoing/acc001"
      }
    ],
    "pgp_public_key": "",
    "pgp_private_key": "",
    "pgp_private_key_passphrase": ""
  }
]
```

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Short unique identifier — used in folder names and database records. Use lowercase letters, numbers, and hyphens only. |
| `name` | No | Display name shown in the dashboard |
| `host` | Yes (sftp mode) | Bank's SFTP hostname |
| `port` | No | Default: 22 |
| `user` | Yes (sftp mode) | SFTP username |
| `pass` | No | SFTP password. Omit if using `key`. |
| `key` | No | Absolute path to SSH private key file. Recommended over password. |
| `inbound_dir` | No | Bank's upload directory (Bridge pushes payment files here). Default: `/inbound` |
| `outbound_dir` | No | Bank's download directory (Bridge pulls statements from here). Default: `/outbound` |
| `accounts` | No | Sub-accounts with their own SFTP subdirectories. Leave as `[]` if none. |
| `pgp_public_key` | No | Absolute path to the bank's PGP public key (encrypts outbound files) |
| `pgp_private_key` | No | Absolute path to your PGP private key (decrypts inbound files from bank) |
| `pgp_private_key_passphrase` | No | Passphrase for the private key, if it has one |
| `known_hosts` | No | Per-bank known_hosts file path. Falls back to global `SFTP_KNOWN_HOSTS`. |

### Adding a new bank to production

**Step 1 — Edit the config file on the server**

```bash
sudo -u bridge nano /opt/bridge/data/banks_config.json
```

Add the new bank object to the JSON array. Validate the JSON before saving:

```bash
python3 -c "import json; json.load(open('/opt/bridge/data/banks_config.json'))" && echo "JSON OK"
```

**Step 2 — Generate SSH keys for the bank connection**

```bash
sudo -u bridge ssh-keygen -t ed25519 -f /opt/bridge/keys/newbank_rsa -N ""
# Print the public key to give to the bank's IT team:
cat /opt/bridge/keys/newbank_rsa.pub
```

Add `"key": "/opt/bridge/keys/newbank_rsa"` to the bank's config entry.

**Step 3 — Capture the bank's SFTP fingerprint**

```bash
# This prevents man-in-the-middle attacks on the SFTP connection
sudo -u bridge ssh-keyscan -p 22 sftp.newbank.com >> /opt/bridge/known_hosts
```

**Step 4 — Restart Bridge to load the new config**

```bash
sudo systemctl restart bridge
sudo journalctl -u bridge -n 20   # confirm the new bank appears in startup logs
```

Expected log line after restart:

```
INFO     Banks reloaded: ['existingbank', 'newbank']
```

---

## 9. Production Deployment on OCI

> This section covers the full first-time setup on a fresh OCI Ubuntu 24.04 VM. If the server is already running, skip to the specific step you need.

### Step 1 — OCI Console setup (do this before touching the server)

1. Go to **Networking → Reserved IPs** and confirm the VM has a Reserved Public IP attached (not ephemeral — a reserved IP survives reboots)
2. Open the **Security List** or NSG for the VM's subnet and add inbound rules:
   - Port 22/TCP — SSH (restrict to your office IP if possible)
   - Port 80/TCP — HTTP (nginx redirect to HTTPS)
   - Port 443/TCP — HTTPS (public)
3. The DNS A record for `rove.banksuite.vantheon.com` must point to the reserved IP. Verify with:
   ```bash
   dig rove.banksuite.vantheon.com
   ```

### Step 2 — OS hardening

SSH into the server as `ubuntu`, then run:

```bash
# Updates and auto-patching
sudo apt update && sudo apt upgrade -y
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP redirect'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw enable

# Harden SSH — edit /etc/ssh/sshd_config and set:
#   PermitRootLogin no
#   PasswordAuthentication no
#   X11Forwarding no
#   AllowUsers ubuntu
#   MaxAuthTries 3
sudo systemctl restart ssh
```

### Step 3 — Install required packages

```bash
sudo apt install -y python3-venv python3-pip postgresql postgresql-contrib \
    nginx certbot python3-certbot-nginx fail2ban
```

### Step 4 — Create the app user and directories

```bash
sudo useradd -r -m -s /bin/bash -d /opt/bridge bridge
sudo passwd -l bridge          # disable password login for this OS user
sudo mkdir -p /opt/bridge
sudo chown bridge:bridge /opt/bridge
```

### Step 5 — Set up PostgreSQL

```bash
sudo systemctl enable --now postgresql

sudo -u postgres psql <<EOF
CREATE USER bridge WITH PASSWORD 'STRONG_DB_PASSWORD_HERE';
CREATE DATABASE bridge OWNER bridge;
REVOKE ALL ON DATABASE bridge FROM PUBLIC;
EOF

# Restrict PostgreSQL to localhost only
# Edit /etc/postgresql/*/main/postgresql.conf:
#   listen_addresses = 'localhost'
# Edit /etc/postgresql/*/main/pg_hba.conf — ensure only:
#   local   bridge   bridge   md5
#   host    bridge   bridge   127.0.0.1/32   md5
sudo systemctl restart postgresql
```

### Step 6 — Deploy the application

```bash
# Copy files from your machine to the server
scp -r bridge/ ubuntu@<server-ip>:/tmp/bridge-deploy
ssh ubuntu@<server-ip>

sudo cp -r /tmp/bridge-deploy/* /opt/bridge/
sudo chown -R bridge:bridge /opt/bridge

# Create virtualenv and install Python packages
sudo -u bridge bash -c "
  cd /opt/bridge
  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
"
```

### Step 7 — Create the `.env` file

```bash
sudo -u bridge tee /opt/bridge/.env > /dev/null <<'EOF'
BRIDGE_MODE=sftp
BIND_HOST=127.0.0.1
SESSION_HTTPS_ONLY=true
SESSION_SECRET=REPLACE_WITH_OUTPUT_OF_python3_-c_import_secrets_print_secrets.token_hex_32

ADMIN_USER=admin
ADMIN_PASS=REPLACE_WITH_STRONG_PASSWORD

PG_HOST=localhost
PG_PORT=5432
PG_DB=bridge
PG_USER=bridge
PG_PASS=STRONG_DB_PASSWORD_HERE

NS_HOST=sftp.your-netsuite.com
NS_PORT=22
NS_USER=ns_sftp_user
NS_KEY=/opt/bridge/keys/netsuite_rsa
NS_OUTBOUND_DIR=/outbound
NS_INBOUND_DIR=/inbound

SFTP_KNOWN_HOSTS=/opt/bridge/known_hosts

BANKS_JSON=[]

POLL_SECONDS=30
MAX_FILES_PER_CYCLE=50
MAX_UPLOAD_BYTES=20971520
MAX_CONCURRENT_SFTP=2
STAGING_MAX_AGE_HOURS=48
EOF

sudo chmod 600 /opt/bridge/.env
sudo chown bridge:bridge /opt/bridge/.env
```

Generate `SESSION_SECRET`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Step 8 — Set up SSH keys for SFTP

```bash
sudo -u bridge mkdir -p /opt/bridge/keys && chmod 700 /opt/bridge/keys

# Key for NetSuite
sudo -u bridge ssh-keygen -t ed25519 -f /opt/bridge/keys/netsuite_rsa -N ""
cat /opt/bridge/keys/netsuite_rsa.pub   # → give to NetSuite admin

# Key per bank (repeat for each)
sudo -u bridge ssh-keygen -t ed25519 -f /opt/bridge/keys/bank1_rsa -N ""
cat /opt/bridge/keys/bank1_rsa.pub      # → give to bank IT team

# Capture server fingerprints (run once per SFTP host)
sudo -u bridge ssh-keyscan -p 22 sftp.your-netsuite.com >> /opt/bridge/known_hosts
sudo -u bridge ssh-keyscan -p 22 sftp.bank1.com >> /opt/bridge/known_hosts
chmod 600 /opt/bridge/known_hosts
```

### Step 9 — Create the systemd service

Create `/etc/systemd/system/bridge.service`:

```ini
[Unit]
Description=Bridge SFTP Middleware
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=bridge
Group=bridge
WorkingDirectory=/opt/bridge
EnvironmentFile=/opt/bridge/.env
ExecStart=/opt/bridge/venv/bin/python bridge.py
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
MemoryMax=512M
CPUQuota=90%
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/bridge/data /opt/bridge/keys
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bridge

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable bridge
sudo systemctl start bridge
sudo systemctl status bridge
```

### Step 10 — Configure nginx and TLS

Add inside the `http {}` block of `/etc/nginx/nginx.conf`:
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
```

Create `/etc/nginx/sites-available/bridge`:

```nginx
server {
    listen 80;
    server_name rove.banksuite.vantheon.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name rove.banksuite.vantheon.com;

    ssl_certificate     /etc/letsencrypt/live/rove.banksuite.vantheon.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rove.banksuite.vantheon.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        client_max_body_size 25M;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/bridge /etc/nginx/sites-enabled/
sudo nginx -t                  # verify config — must say "test is successful"
sudo systemctl reload nginx

# Issue TLS certificate
sudo certbot --nginx -d rove.banksuite.vantheon.com \
    --non-interactive --agree-tos -m admin@vantheon.com

# Verify auto-renewal timer
sudo systemctl status certbot.timer
```

### Step 11 — Configure fail2ban

Create `/etc/fail2ban/jail.d/bridge.conf`:

```ini
[bridge-login]
enabled  = true
port     = 443
filter   = bridge-login
logpath  = /var/log/nginx/access.log
maxretry = 10
bantime  = 600
findtime = 300

[sshd]
enabled  = true
maxretry = 5
bantime  = 3600
```

Create `/etc/fail2ban/filter.d/bridge-login.conf`:

```ini
[Definition]
failregex = ^<HOST> .* "POST /login HTTP.*" 401
```

```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status
```

---

## 10. First Login and User Setup

1. Open `https://rove.banksuite.vantheon.com` in your browser
2. Log in with `ADMIN_USER` / `ADMIN_PASS` from `.env`
3. On first login, you are redirected to **MFA Setup** — scan the QR code with Google Authenticator or Authy
4. Enter the 6-digit code to complete enrollment
5. Go to the **Users** section (header) to create named operator accounts
6. Each new user completes their own MFA enrollment on first login
7. Once named admin accounts exist, avoid sharing the generic `admin` account

> **MFA** (Multi-Factor Authentication) = You need both your password AND a time-based 6-digit code from your phone to log in. This protects the dashboard even if a password is compromised.

---

## 11. Features and Functionality

### Dashboard (`https://rove.banksuite.vantheon.com`)

| Feature | Description |
|---|---|
| Summary cards | Live counts of Sent / Received / Failed / Pending / Duplicate transfers |
| Transfer table | Paginated list, auto-refreshes every 3 seconds, filterable by status / direction / bank |
| Transfer detail | Click the info icon to see full event logs, SHA-256 hashes, timestamps, and error text |
| Retry | Re-attempt a failed transfer (staged file must still exist on disk) — admin only |
| Abandon | Move a failed transfer to `data/error/` and mark it abandoned — admin only |
| Delete | Delete a transfer record and its staged file — admin only |
| Manual upload | Inject a file directly into the pipeline with a chosen bank and direction |
| Folder browser | Browse `data/netsuite/`, `data/processed/`, `data/error/` directory trees |
| User management | Create, delete, reset passwords for operator accounts — admin only |
| Health indicator | Shows PostgreSQL connection status in the page header |
| Notifications bar | Shows recent failures and duplicates at the top of the page |

### Transfer statuses

| Status | Meaning |
|---|---|
| `pending` | File recorded in database, waiting to be delivered |
| `transferring` | Delivery is in progress right now |
| `sent` | Delivered to bank SFTP successfully (outbound) |
| `received` | Delivered to NetSuite SFTP successfully (inbound) |
| `failed` | Delivery failed — retryable if staged file still exists |
| `duplicate` | Same file content detected before — blocked, not delivered |
| `abandoned` | Admin wrote it off; file is in `data/error/` |

### User roles

| Role | Permissions |
|---|---|
| `admin` | Full access: view, retry, abandon, delete, upload, manage users |
| `readonly` | View transfers, browse folders, check notifications only |

---

## 12. API Reference

All API endpoints require an active session (log in via the web UI first). All responses are JSON.

### Health check

```http
GET /api/health
```
```json
{"status": "ok", "postgres": true}
```
Returns `{"status": "degraded", "postgres": false}` if PostgreSQL is unreachable. Use this for monitoring probes.

---

### Transfer summary

```http
GET /api/summary
```
```json
{
  "total": 284,
  "sent": 150,
  "received": 120,
  "failed": 4,
  "pending": 0,
  "transferring": 0,
  "duplicate": 8,
  "abandoned": 2
}
```

---

### List transfers

```http
GET /api/transfers?status=failed&direction=outbound&bank_id=hsbc&page=1&per_page=50
```

All query parameters are optional:

| Parameter | Values | Description |
|---|---|---|
| `status` | `pending`, `sent`, `received`, `failed`, `duplicate`, `abandoned`, `transferring` | Filter by status |
| `direction` | `outbound`, `inbound` | Filter by direction |
| `bank_id` | any bank ID string | Filter by bank |
| `page` | integer ≥ 1 | Page number (default: 1) |
| `per_page` | 1–200 | Results per page (default: 50) |

```json
{
  "items": [
    {
      "id": 42,
      "filename": "payment_20260512.csv",
      "direction": "outbound",
      "status": "failed",
      "size_bytes": 4096,
      "sha256": "a1b2c3d4...",
      "content_sha256": "e5f6a7b8...",
      "error": "Connection timed out",
      "retries": 1,
      "bank_id": "hsbc",
      "account_id": "acc001",
      "updated_at": "2026-05-12 10:30:00 UTC"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 50
}
```

---

### Transfer detail

```http
GET /api/transfers/{id}
```
```json
{
  "id": 42,
  "filename": "payment_20260512.csv",
  "direction": "outbound",
  "status": "failed",
  "size_bytes": 4096,
  "sha256": "a1b2c3...",
  "content_sha256": "e5f6a7...",
  "error": "Connection timed out",
  "retries": 1,
  "staged_path": "/opt/bridge/data/staging/abc123_payment_20260512.csv",
  "archived_path": null,
  "bank_id": "hsbc",
  "account_id": "acc001",
  "created_at": "2026-05-12 10:00:00 UTC",
  "updated_at": "2026-05-12 10:00:31 UTC",
  "logs": [
    {"message": "Discovered: payment_20260512.csv (4096B, bank=hsbc, account=acc001)", "time": "2026-05-12 10:00:00 UTC"},
    {"message": "Transferring...", "time": "2026-05-12 10:00:01 UTC"},
    {"message": "Failed: Connection timed out", "time": "2026-05-12 10:00:31 UTC"}
  ]
}
```

---

### Retry a failed transfer (admin only)

```http
POST /api/transfers/{id}/retry
```

Success:
```json
{"ok": true, "message": "Transfer succeeded"}
```

Failure (HTTP 400):
```json
{"ok": false, "message": "Staged file no longer exists — please re-upload"}
```

---

### Abandon a failed transfer (admin only)

```http
POST /api/transfers/{id}/abandon
```
```json
{"ok": true, "archived_path": "/opt/bridge/data/error/2026-05-12/hsbc/acc001/outbound/payment.csv"}
```

---

### Delete a transfer record (admin only)

```http
DELETE /api/transfers/{id}
```
```json
{"ok": true, "message": "Transfer #42 deleted"}
```

---

### Manual file upload

```http
POST /api/upload
Content-Type: multipart/form-data

file        = <file>
direction   = outbound | inbound
bank_id     = hsbc          (optional — defaults to first configured bank)
account_id  = acc001        (optional)
```

```json
{
  "queued": "payment.csv",
  "stored_as": "20260512100000000000_abc123_payment.csv",
  "direction": "outbound",
  "bank_id": "hsbc"
}
```

---

### Folder browser

```http
GET /api/folders?path=
GET /api/folders?path=netsuite
GET /api/folders?path=netsuite/hsbc/ACK
```

Available roots: `netsuite`, `processed`, `error`

```json
{
  "path": "netsuite/hsbc/ACK",
  "entries": [
    {"name": "42_payment_20260512.csv", "type": "file", "size": 4096, "mtime": 1715506800}
  ]
}
```

---

### User management (admin only)

```http
GET    /api/users
POST   /api/users                         Body: {"username":"ops1","password":"...","role":"readonly"}
DELETE /api/users/{username}
POST   /api/users/{username}/reset-password   Body: {"password":"newpassword"}
```

---

### Current user info

```http
GET /api/me
```
```json
{"user": "ops1", "role": "readonly"}
```

---

## 13. Architecture Deep Dive

### Single-file design

The entire application is in `bridge.py` (~2000 lines). There are no sub-packages. All configuration, database logic, SFTP handling, transfer pipeline, and web routes are in this one file. This makes auditing straightforward but means all changes happen in one place.

### Execution model

```
bridge.py (entry point: python bridge.py)
│
├── FastAPI app (HTTP on port 8000)
│   ├── Serves dashboard HTML via Jinja2 templates
│   └── Handles /api/* JSON endpoints
│
├── asyncio task: poll_loop()       ← runs continuously in background
│   └── Every 30s: _poll_cycle()
│       ├── For each bank → for each account:
│       │   ├── NS SFTP poll (outbound files) → process_file()
│       │   └── Bank SFTP poll (inbound files) → process_file()
│       └── Writes results to PostgreSQL
│
└── asyncio task: _staging_cleanup_loop()
    └── Every 1 hour: removes orphaned staging files older than 48h
```

> **asyncio** = Python's built-in system for running multiple things at once without multiple threads. The web server and the poll loop share the same thread and take turns using it.

### Connection management

No persistent SFTP connections. For every poll cycle, Bridge opens a fresh SFTP connection, downloads all pending files, then closes it. The semaphore `_SFTP_SEM` limits the total number of simultaneous open connections to `MAX_CONCURRENT_SFTP` (default 2).

### Key functions and their responsibilities

| Function | File line | What it does |
|---|---|---|
| `lifespan()` | ~1352 | FastAPI startup: loads config, initialises DB, starts background tasks |
| `_load_banks_config()` | ~109 | Reads banks from `banks_config.json` → `BANKS_JSON` → `BANK_*` env vars |
| `_poll_cycle()` | ~1188 | One full poll of all SFTP sources for all banks |
| `process_file()` | ~1093 | Hash → dedup check → record in DB → call `_deliver()` |
| `_deliver()` | ~964 | PGP encrypt/decrypt if configured → SFTP upload → archive → ACK/NACK |
| `DB.insert_or_detect_duplicate()` | ~559 | Advisory lock + duplicate check + DB insert |
| `_archive_file()` | ~211 | Moves staged file to `data/processed/` with date/bank/direction path |
| `write_ack()` / `write_nack()` | ~825 | Copies file to ACK or NACK folder under `data/netsuite/` |
| `sftp_connect()` | ~770 | Opens asyncssh SFTP connection with key or password auth |
| `_safe_id()` | ~185 | Sanitizes bank/account IDs for safe filesystem use |
| `canonicalize_for_duplicate_hash()` | ~752 | Normalizes text file content before hashing for dedup |

---

## 14. Data Flow Walkthrough

### Outbound: NetSuite → Bank

```
POLL (every 30s)
  └── _poll_cycle() iterates: for bank in BANKS → for account in bank.accounts

DISCOVER
  └── asyncssh connects to NS_HOST
      sftp.readdir("/outbound/hsbc/acc001") → ["payment.csv"]
      sftp.get("payment.csv") → data/staging/<uuid>_payment.csv
      sftp.remove("payment.csv")  ← file deleted from NetSuite SFTP immediately

HASH
  └── sha256         = hashlib.sha256(raw_bytes).hexdigest()
      content_sha256 = sha256 of (normalized line endings + trimmed whitespace)

DEDUP CHECK
  └── PostgreSQL: pg_advisory_xact_lock(hashtext(content_sha256))
      SELECT ... WHERE content_sha256 = ? AND direction = 'outbound' AND bank_id = 'hsbc'
      → No match → INSERT status='pending'

DELIVER
  └── [optional] PGP encrypt with bank's public key → staging/<uuid>_payment.csv.pgp
      asyncssh connects to bank SFTP
      sftp.put(local_file, "/incoming/payment.csv")
      temp .pgp file deleted

ARCHIVE
  └── shutil.move(staged_file) → data/processed/2026-05-12/hsbc/acc001/outbound/payment.csv

ACK
  └── shutil.copy(archived_file) → data/netsuite/hsbc/acc001/ACK/42_payment.csv

COMPLETE
  └── UPDATE transfers SET status='sent', archived_path=...
```

### Inbound: Bank → NetSuite

```
POLL
  └── asyncssh connects to bank SFTP
      sftp.readdir("/outgoing") → ["statement.mt940"]
      sftp.get("statement.mt940") → data/staging/<uuid>_statement.mt940
      sftp.remove("statement.mt940")  ← file deleted from bank SFTP immediately

HASH + DEDUP CHECK (same as outbound, direction='inbound')

DECRYPT (if applicable)
  └── If filename ends in .pgp → _pgp_decrypt_file() using bank's private key

ROUTE
  └── If "_nack" in filename → deliver to data/netsuite/hsbc/NACK/ or NS SFTP .../NACK/
      Otherwise → normal inbound delivery

DELIVER
  └── asyncssh connects to NS_HOST
      sftp.put(local_file, "/inbound/hsbc/acc001/statement.mt940")

ARCHIVE + COMPLETE
  └── data/processed/2026-05-12/hsbc/acc001/inbound/statement.mt940
      UPDATE transfers SET status='received'
```

### On failure

- `status` → `'failed'`, error message stored in the `error` column
- Staged file is kept (not deleted) — retry is possible as long as the file exists
- `write_nack()` copies the staged file to `data/netsuite/<bank>/NACK/`
- The poll loop continues to the next bank — one failure does not block others
- Automatic retry does not happen; an operator must click **Retry** in the dashboard

### Duplicate detection

`content_sha256` is computed after normalizing the file content:
- UTF-8 BOM stripped
- `\r\n` and `\r` converted to `\n`
- Trailing spaces removed from each line
- Trailing blank lines removed

This means a CSV file resent with different line endings (Windows vs Unix) is still caught as a duplicate. Binary files (containing null bytes `\x00`) skip normalization and are hashed as-is.

---

## 15. PGP Encryption Support

Optional per-bank PGP encryption for payment files and decryption for statement files.

> **PGP** = Pretty Good Privacy. An encryption standard using key pairs: a public key (you share with the bank) to encrypt, and a private key (you keep secret) to decrypt.

### Outbound encryption (your files → bank)

The bank gives you their public key. Bridge encrypts each payment file before uploading:

```json
{"pgp_public_key": "/opt/bridge/keys/bankname_pubkey.asc"}
```

Encrypted files are uploaded with `.pgp` appended to the filename (e.g. `payment.csv.pgp`). The temp encrypted file is deleted from staging after upload.

### Inbound decryption (bank files → you)

You give the bank your public key. The bank encrypts statements. Bridge decrypts before forwarding to NetSuite:

```json
{
  "pgp_private_key": "/opt/bridge/keys/bridge_privkey.asc",
  "pgp_private_key_passphrase": "passphrase_if_key_requires_it"
}
```

Files ending in `.pgp` are automatically detected and decrypted. If no private key is configured, `.pgp` files are forwarded as-is.

PGP operations use a local GPG keyring at `data/gnupg/` (permissions: `700`). Keys are imported on each operation.

---

## 16. Troubleshooting — Logs, Database, and Diagnostics

This section is a practical guide to diagnosing real problems. Start with the system logs, then query the database, then inspect the filesystem.

---

### 16.1 System service checks (always start here)

```bash
# Is the service running?
sudo systemctl status bridge

# Live log stream (Ctrl+C to stop)
sudo journalctl -u bridge -f

# Last 100 log lines
sudo journalctl -u bridge -n 100 --no-pager

# All logs from the last hour
sudo journalctl -u bridge --since "1 hour ago" --no-pager

# All logs from a specific time window
sudo journalctl -u bridge --since "2026-05-12 09:00:00" --until "2026-05-12 10:00:00" --no-pager

# All ERROR-level lines only
sudo journalctl -u bridge --no-pager | grep -i " ERROR "

# All lines related to a specific file
sudo journalctl -u bridge --no-pager | grep "payment_20260512.csv"

# All SFTP-related errors
sudo journalctl -u bridge --no-pager | grep -E "(poll error|SFTP|sftp|Connection|timeout)"

# Duplicate detections
sudo journalctl -u bridge --no-pager | grep "DUPLICATE"
```

---

### 16.2 Reading log output

**Startup messages to expect:**

```
INFO     PostgreSQL connected (bridge@localhost/bridge)
INFO     Database ready
INFO     Loaded 2 bank(s) from data/banks_config.json
INFO     Poller started (every 30s, mode=sftp, ns=sftp-client (bridge dials out), banks=2, segregation=True)
```

**Normal poll activity (files transferred):**

```
INFO     OUTBOUND  payment.csv (4096B, bank=hsbc, sha=a1b2c3d4...)
INFO     Poll cycle: processed 1 file(s)
```

**Warning: no SFTP known_hosts configured:**

```
WARNING  SFTP to sftp.hsbc.com: no known_hosts file configured — host key not verified
```

→ Fix: run `ssh-keyscan` to populate `/opt/bridge/known_hosts` (see Section 9 Step 8).

**SFTP connection failure:**

```
ERROR    NS poll error (bank=hsbc, acct=acc001): [Errno 111] Connection refused
ERROR    Bank poll error (bank=hsbc, acct=acc001): timed out
```

→ Check network connectivity, credentials, and that the remote SFTP port is open.

**Duplicate blocked:**

```
WARNING  DUPLICATE: payment.csv matches #42 (payment.csv, status=sent)
```

→ Expected if the same file was re-submitted. Check transfer #42 in the dashboard.

**Stuck in transferring (app crashed mid-transfer):**

```
# Nothing — the crash left the DB record at status='transferring'
# Restart the service and manually retry from the dashboard.
```

---

### 16.3 Database diagnostics

Connect to the database as the bridge user:

```bash
sudo -u postgres psql -d bridge
# or with password:
PGPASSWORD=your_db_password psql -h localhost -U bridge -d bridge
```

#### Count transfers by status

```sql
SELECT status, COUNT(*) AS count
FROM transfers
GROUP BY status
ORDER BY count DESC;
```

#### Recent transfers (last 50)

```sql
SELECT id, filename, direction, status, bank_id, account_id, error,
       updated_at
FROM transfers
ORDER BY id DESC
LIMIT 50;
```

#### All failed transfers

```sql
SELECT id, filename, direction, bank_id, account_id, error,
       retries, staged_path, updated_at
FROM transfers
WHERE status = 'failed'
ORDER BY id DESC;
```

#### All transfers stuck in 'transferring'

```sql
SELECT id, filename, direction, bank_id, updated_at
FROM transfers
WHERE status = 'transferring'
ORDER BY updated_at;
```

A record stuck in `transferring` means the app crashed or was restarted mid-transfer. Reset it so it can be retried:

```sql
-- Reset to 'failed' so the Retry button becomes available
UPDATE transfers
SET status = 'failed', error = 'Reset after crash/restart'
WHERE status = 'transferring';
```

> Only run this when you are sure the service is not actively processing those transfers. It is safe to run immediately after a restart.

#### Full event log for a specific transfer

```sql
SELECT t.id, t.filename, t.direction, t.status, t.bank_id,
       t.account_id, t.error, t.staged_path, t.archived_path,
       t.retries, t.created_at, t.updated_at
FROM transfers t
WHERE t.id = 42;

-- Event log for that transfer
SELECT message, created_at
FROM transfer_logs
WHERE transfer_id = 42
ORDER BY created_at;
```

#### Find a transfer by filename

```sql
SELECT id, filename, direction, status, bank_id, error, updated_at
FROM transfers
WHERE filename ILIKE '%payment_20260512%'
ORDER BY id DESC;
```

#### Check for duplicates of a specific file

```sql
-- First get the content hash of the original
SELECT id, filename, content_sha256, status
FROM transfers
WHERE filename = 'payment_20260512.csv';

-- Then find all transfers with that same content hash
SELECT id, filename, direction, bank_id, status, created_at
FROM transfers
WHERE content_sha256 = 'paste_hash_here'
ORDER BY id;
```

#### Transfers by bank with failure count

```sql
SELECT bank_id,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE status = 'sent')     AS sent,
       COUNT(*) FILTER (WHERE status = 'received') AS received,
       COUNT(*) FILTER (WHERE status = 'failed')   AS failed,
       COUNT(*) FILTER (WHERE status = 'duplicate') AS duplicate
FROM transfers
GROUP BY bank_id
ORDER BY total DESC;
```

#### Recent failures in the last 24 hours

```sql
SELECT id, filename, direction, bank_id, error, updated_at
FROM transfers
WHERE status = 'failed'
  AND updated_at > NOW() - INTERVAL '24 hours'
ORDER BY updated_at DESC;
```

#### Find transfers with no staged file (cannot be retried without re-upload)

```sql
SELECT id, filename, direction, bank_id, staged_path, updated_at
FROM transfers
WHERE status = 'failed'
  AND (staged_path IS NULL OR staged_path = '')
ORDER BY id DESC;
```

#### Check database size

```sql
SELECT pg_size_pretty(pg_database_size('bridge')) AS database_size;

SELECT pg_size_pretty(pg_total_relation_size('transfers')) AS transfers_table_size;
SELECT pg_size_pretty(pg_total_relation_size('transfer_logs')) AS logs_table_size;
```

#### List all users and MFA status

```sql
SELECT username, role, mfa_enabled, last_login_at, created_at
FROM users
ORDER BY created_at;
```

#### Reset a user's MFA (if they lose their authenticator app)

```sql
-- This forces re-enrollment on next login
UPDATE users
SET mfa_secret = NULL, mfa_enabled = FALSE
WHERE username = 'ops1';
```

> The operator must then log in with just their password and the MFA setup screen will appear again.

#### Check transfer_logs for errors in the last hour

```sql
SELECT t.id, t.filename, t.bank_id, tl.message, tl.created_at
FROM transfer_logs tl
JOIN transfers t ON t.id = tl.transfer_id
WHERE tl.message ILIKE '%fail%' OR tl.message ILIKE '%error%'
  AND tl.created_at > NOW() - INTERVAL '1 hour'
ORDER BY tl.created_at DESC
LIMIT 50;
```

---

### 16.4 Filesystem checks

```bash
# Check all data directory sizes
du -sh /opt/bridge/data/*/

# Check staging directory — should normally be empty or near-empty
ls -lah /opt/bridge/data/staging/
ls -lah /opt/bridge/data/upload_staging/

# Check ACK files for a specific bank
ls -lah /opt/bridge/data/netsuite/hsbc/ACK/

# Check NACK files (delivery failures)
ls -lah /opt/bridge/data/netsuite/hsbc/NACK/

# Find staging files older than 2 days (these should have been cleaned up)
find /opt/bridge/data/staging -mtime +2 -type f

# Find large files in processed archive
find /opt/bridge/data/processed -type f -size +10M

# Check banks_config.json is valid JSON
python3 -c "import json; json.load(open('/opt/bridge/data/banks_config.json'))" && echo "Valid"

# Check .env is readable by the bridge user
sudo -u bridge cat /opt/bridge/.env > /dev/null && echo "Readable"
```

---

### 16.5 SFTP connectivity checks

Test SFTP connections manually as the `bridge` user to rule out credential or network issues:

```bash
# Test NetSuite SFTP with key auth
sudo -u bridge sftp -i /opt/bridge/keys/netsuite_rsa -P 22 ns_user@sftp.netsuite.com

# Test bank SFTP with key auth
sudo -u bridge sftp -i /opt/bridge/keys/hsbc_rsa -P 22 user@sftp.hsbc.com

# If sftp is not available, test basic SSH connectivity
sudo -u bridge ssh -v -i /opt/bridge/keys/netsuite_rsa -p 22 ns_user@sftp.netsuite.com 2>&1 | head -40
```

Once connected to the SFTP prompt, verify the expected directories exist:

```
sftp> ls /outbound
sftp> ls /inbound
sftp> exit
```

---

### 16.6 Common problems and solutions

#### "Files are not being picked up from NetSuite"

1. Confirm `BRIDGE_MODE=sftp` in `.env` (not `MODE=sftp` — that has no effect):
   ```bash
   grep BRIDGE_MODE /opt/bridge/.env
   ```

2. Check logs for poll errors:
   ```bash
   sudo journalctl -u bridge -n 50 | grep -E "poll error|NS poll"
   ```

3. Verify the correct remote directory is being polled. With `SFTP_FOLDER_SEGREGATION=true` (the default), Bridge looks at `/outbound/<bank_id>/<account_id>` on NetSuite's SFTP, not just `/outbound`:
   ```bash
   sudo journalctl -u bridge -n 50 | grep "sftp_remote_dir"
   # Or check the code: SFTP_FOLDER_SEGREGATION defaults to true
   ```

4. Check if `data/banks_config.json` has incorrect directory settings:
   ```bash
   cat /opt/bridge/data/banks_config.json | python3 -m json.tool | grep -E "outbound|inbound"
   ```

#### "Transfers keep failing with 'Connection timed out'"

1. Check that the bank's SFTP server allows connections from this server's IP:
   ```bash
   curl ifconfig.me    # your server's public IP — give this to the bank
   ```

2. Test raw TCP connectivity to the bank's SFTP port:
   ```bash
   nc -zv sftp.hsbc.com 22
   ```

3. Check OCI Security List rules — outbound connections must be allowed.

#### "Dashboard shows a transfer as 'transferring' and it's stuck"

The app was restarted or crashed while delivering. Reset the stuck record:

```sql
UPDATE transfers
SET status = 'failed', error = 'Reset after restart — retry manually'
WHERE status = 'transferring';
```

Then use the Retry button in the dashboard.

#### "Retry says 'No staged file on record — please re-upload'"

The staged file path recorded in the database is blank (the transfer was created before staged path tracking was added). Re-upload the file via the dashboard upload button.

#### "Retry says 'Staged file no longer exists'"

The file was deleted from `data/staging/` — either by the hourly cleanup loop (files older than 48 hours) or manually. Re-upload the file.

#### "Login rate-limit triggered after restart"

The rate-limit counter is in-memory and resets when the service restarts:

```bash
sudo systemctl restart bridge
```

Or wait 5 minutes for the lockout to expire.

#### "Service fails to start"

```bash
sudo systemctl status bridge         # read the exit code and last message
sudo journalctl -u bridge -n 30      # read the startup error

# Common causes:
# 1. WorkingDirectory wrong — must be /opt/bridge
grep WorkingDirectory /etc/systemd/system/bridge.service

# 2. PostgreSQL not running
sudo systemctl status postgresql

# 3. .env file missing or not readable
ls -la /opt/bridge/.env
sudo -u bridge cat /opt/bridge/.env > /dev/null

# 4. Python venv missing
ls /opt/bridge/venv/bin/python
```

#### "Dashboard shows 'postgres: false' in health indicator"

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
PGPASSWORD=your_pass psql -h localhost -U bridge -d bridge -c "SELECT 1;"

# Check pg_hba.conf allows the bridge user
sudo cat /etc/postgresql/*/main/pg_hba.conf | grep bridge

# Check PG_PASS in .env matches the actual PostgreSQL password
grep PG_PASS /opt/bridge/.env
```

#### "nginx returns 502 Bad Gateway"

The Bridge app is not running or not listening on port 8000:

```bash
sudo systemctl status bridge
sudo ss -tlnp | grep 8000   # confirm bridge is listening
sudo journalctl -u bridge -n 20
```

#### "TLS certificate expired"

```bash
sudo certbot certificates             # check expiry dates
sudo systemctl status certbot.timer   # check auto-renewal is active
sudo certbot renew --dry-run          # test renewal
sudo certbot renew                    # force renew if needed
sudo systemctl reload nginx
```

---

## 17. Security Notes

### Measures already in place

| Layer | What is configured |
|---|---|
| OS | ufw firewall (ports 22/80/443 only), SSH key-only login, unattended security updates |
| App login | bcrypt passwords + mandatory TOTP MFA for all users |
| Sessions | `SameSite=strict` cookie, HTTPS-only flag, 8-hour expiry |
| Rate limiting | nginx: 10 login requests/minute; app: 5 failures → 5-minute lockout per username |
| SFTP | SSH key authentication recommended; known_hosts file for fingerprint verification |
| Duplicate detection | SHA-256 content hash + PostgreSQL advisory lock (prevents race conditions) |
| Path safety | `_safe_id()` sanitizes all bank/account IDs; `Path().name` strips directory components from remote filenames |
| Secrets | `.env` file chmod 600, owned by `bridge` user; `data/gnupg/` chmod 700 |
| Process isolation | systemd: `ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`, `MemoryMax=512M` |
| TLS | Let's Encrypt, TLS 1.2/1.3 only, HSTS header |
| Database | PostgreSQL on localhost only, dedicated low-privilege `bridge` user |
| Brute-force | fail2ban bans IPs after repeated login failures |

### What you are responsible for

1. **`SFTP_KNOWN_HOSTS`** — without it, SFTP connections proceed without verifying the remote server's identity. The app logs a warning but does not block. Set this before going live.

2. **`data/banks_config.json`** contains SFTP credentials and PGP key paths in plain text. Keep it restricted:
   ```bash
   chmod 600 /opt/bridge/data/banks_config.json
   chown bridge:bridge /opt/bridge/data/banks_config.json
   ```

3. **SSH key permissions** — private keys must be `chmod 600`:
   ```bash
   chmod 600 /opt/bridge/keys/*
   ```

4. **Change `ADMIN_PASS`** immediately after first login.

5. **Database backups** — no automated backup is included. Set up a scheduled backup.

---

## 18. Best Practices and Operational Notes

### The `WorkingDirectory` setting is critical

All paths in Bridge are relative to the working directory. The systemd service must have `WorkingDirectory=/opt/bridge`. If this is missing or wrong, `data/` directories are created in the wrong place and files go missing silently.

Always confirm:
```bash
grep WorkingDirectory /etc/systemd/system/bridge.service
```

### `data/banks_config.json` takes priority over `BANKS_JSON`

If both exist, `data/banks_config.json` always wins. This file is created the first time the bank config API endpoint is called. When deploying a config change via `.env`, check if this file exists and either update it directly or delete it (it will be recreated from `BANKS_JSON` on next startup):

```bash
ls -la /opt/bridge/data/banks_config.json
```

### Files are deleted from source immediately after download

Both NetSuite SFTP and bank SFTP files are removed (`sftp.remove()`) as soon as Bridge downloads them to `data/staging/`. There is no undo. The staged copy is the only copy Bridge holds.

Do not delete files from `data/staging/` manually. The cleanup loop removes them after 48 hours only if they have no active DB record.

### Stuck 'transferring' records after restart

After every unplanned restart, query for stuck records and reset them before operators start retrying:

```sql
UPDATE transfers
SET status = 'failed', error = 'Reset after restart'
WHERE status = 'transferring';
```

### Session secret must be set

Without `SESSION_SECRET` set in `.env`, every restart generates a new random secret and all logged-in users are immediately logged out. Set a stable value:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Paste output as SESSION_SECRET in .env
```

### Deploy a new `bridge.py`

```bash
# Copy the new file
sudo cp /tmp/bridge.py /opt/bridge/bridge.py
sudo chown bridge:bridge /opt/bridge/bridge.py

# Restart
sudo systemctl restart bridge

# Confirm clean startup
sudo journalctl -u bridge -n 20
```

### Avoid bulk-deleting transfer records

The database is the complete audit trail. Deleting records removes the history permanently. Only delete individual records through the dashboard when you have a specific reason (e.g. a test record).

---

## 19. Maintenance Reference

### Quick status checks

```bash
# Service
sudo systemctl status bridge

# Live logs
sudo journalctl -u bridge -f

# Health API
curl -sk https://rove.banksuite.vantheon.com/api/health

# Disk usage
du -sh /opt/bridge/data/*/

# PostgreSQL
sudo systemctl status postgresql
```

### Regular maintenance tasks

| Task | Command |
|---|---|
| View live logs | `sudo journalctl -u bridge -f` |
| Restart service | `sudo systemctl restart bridge` |
| Deploy new bridge.py | `sudo cp bridge.py /opt/bridge/ && sudo systemctl restart bridge` |
| Database backup | `PGPASSWORD=pass pg_dump -h localhost -U bridge bridge > bridge_$(date +%F).sql` |
| Check TLS expiry | `sudo certbot certificates` |
| Renew TLS manually | `sudo certbot renew && sudo systemctl reload nginx` |
| Check fail2ban | `sudo fail2ban-client status bridge-login` |
| Unban an IP | `sudo fail2ban-client set bridge-login unbanip <ip>` |
| Check firewall | `sudo ufw status verbose` |

### Clean up old archive files

ACK, NACK, and processed files are under `data/netsuite/` and `data/processed/`:

```bash
# Remove ACK/NACK files older than 90 days
find /opt/bridge/data/netsuite -type f -mtime +90 -delete

# Remove processed archive files older than 1 year
find /opt/bridge/data/processed -type f -mtime +365 -delete

# Clean up empty directories after file deletion
find /opt/bridge/data/netsuite -type d -empty -delete
find /opt/bridge/data/processed -type d -empty -delete
```

> **Note:** The paths for ACK/NACK are `data/netsuite/<bank>/ACK/` and `data/netsuite/<bank>/NACK/`. There are no top-level `data/ACK/` or `data/NACK/` directories.

### Purge old transfer log records (keep transfers, remove verbose logs)

```sql
-- Remove per-event logs older than 6 months, keeping the transfer records themselves
DELETE FROM transfer_logs
WHERE created_at < NOW() - INTERVAL '6 months';

-- Check how many log rows remain
SELECT COUNT(*) FROM transfer_logs;
```
