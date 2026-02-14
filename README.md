# WordPanel 🚀

**WordPanel** is a lightweight, modern web interface for [WordOps](https://wordops.net/), designed to simplify WordPress server management. Built with **FastAPI**, **HTMX**, and **Tailwind CSS**, it provides a streamlined dashboard for deploying sites, managing assets, and handling server administration without touching the command line.

---

## ✨ Key Features

* **🖥️ Site Dashboard:** View all WordOps sites, SSL status, and PHP/Cache types at a glance.
* **⚡ One-Click WP-Admin:** deeply integrated "Auto-Login" button that generates a magic link to any site's WordPress dashboard.
* **📦 Asset Vault:** Upload and manage premium `.zip` plugins and themes centrally on the server.
* **🚀 Smart Deployment:**
* Create sites with Nginx FastCGI or Redis Cache stacks.
* **Hybrid Installer:** specific plugins from the WordPress Repository *and* your local Asset Vault simultaneously during site creation.
* Auto-activate selected plugins upon deployment.


* **👥 Team Management:** Create multiple administrator accounts with secure authentication (Argon2 hashing).
* **🔒 Security:** JWT-based stateless authentication and protected routes.
* **🛠️ System Integration:** Runs as a native systemd service (`wordpanel.service`).

---

## 🛠️ Tech Stack

* **Backend:** Python 3.12 + FastAPI
* **Database:** SQLite (Lightweight, file-based storage)
* **Frontend:** HTML5, Tailwind CSS (Styling), HTMX (Dynamic interactions), Alpine.js (Modal logic)
* **Server Core:** WordOps (WP-CLI, Nginx)
* **Packaging:** Debian Package (`.deb`) with auto-venv creation.

---

## 📥 Installation

### 1. Prerequisites (Required)
WordPanel is a control panel *for* WordOps. You must have WordOps installed on your server first.

**Install WordOps:**
```bash
# Official WordOps One-Step Installer
wget -qO wo wops.cc && sudo bash wo
```
WordPanel is distributed as a custom Debian package.

### 2. Download the package

Navigate to the parent directory of your source code:

Download the installer [Releases](https://github.com/qrussell/wordpanel/releases)

### 3. Install the Package

```bash
sudo apt install ./wordpanel-1.0.deb

```

*During installation, the package will automatically create a secure Python virtual environment in `/opt/wordpanel/venv`, install dependencies, and start the systemd service.*

### 4. Firewall Setup

Ensure port **8000** is open on your server:

```bash
sudo ufw allow 8000/tcp
sudo ufw reload

```

---

## 🚦 Usage

### Accessing the Dashboard

Open your browser and navigate to:
`http://<YOUR_SERVER_IP>:8000`

### Default Credentials

* **Username:** `admin`
* **Password:** `admin`

*(⚠️ Security Note: Create a new admin user and delete the default `admin` account immediately after your first login.)*

### Deploying a Site

1. Click **New Site**.
2. Enter the Domain, User, and Email.
3. Select your Stack (FastCGI or Redis).
4. **Deployment Assets:**
* **Green Dot:** Plugins pulled from the WordPress Repo.
* **Purple Dot:** Custom Zips from your Vault.
* Check **Install** to add them, and **Activate** to enable them instantly.



---

## 📂 Project Structure

```text
/opt/wordpanel
├── main.py                 # Application entry point & API routes
├── auth.py                 # JWT Auth, Password Hashing (Argon2), DB Logic
├── templates/              # Jinja2 HTML Templates
│   ├── index.html          # Main Dashboard
│   ├── login.html          # Login Page
│   ├── modal.html          # Site Management Modal
│   └── asset_list_fragment.html # HTMX Fragment for Vault
└── venv/                   # (Created on install) Python Environment

```

---

## 🧑‍💻 Development

To run WordPanel locally for development without building the package:

1. **Clone & Setup:**
```bash
git clone https://github.com/qrussell/wordpanel.git
cd wordpanel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```


2. **Run with Uvicorn (Hot Reload):**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000

```



---

## 📝 License

This project is proprietary software for internal server management.
*(Or add MIT/GPL license here if you plan to open source it)*.
