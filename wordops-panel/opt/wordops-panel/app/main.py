import subprocess
import sqlite3
import os
import shutil
import requests
import yaml
import json
import base64
import socket
from fastapi import UploadFile, File
from fastapi import FastAPI, Request, Form, BackgroundTasks, Depends, HTTPException, status, Response
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt, JWTError

# Import our custom Auth module
from auth import (
    init_user_db as auth_init_db, verify_password, create_access_token, 
    list_users, add_user, delete_user, 
    SECRET_KEY, ALGORITHM
)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- CONFIGURATION ---
ASSET_DIR = "/var/lib/wordops-panel/assets"
DB_PATH = "/var/lib/wo/wordops-panel_users.db"
REPO_PLUGINS = [
    {"name": "Elementor", "slug": "elementor", "type": "plugin"},
    {"name": "Yoast SEO", "slug": "wordpress-seo", "type": "plugin"},
    {"name": "WooCommerce", "slug": "woocommerce", "type": "plugin"},
    {"name": "Wordfence", "slug": "wordfence", "type": "plugin"},
    {"name": "Classic Editor", "slug": "classic-editor", "type": "plugin"},
]

# --- GLOBAL STATE ---
deployment_progress = {}

# --- DATABASE & SETTINGS HELPERS ---
def init_db():
    auth_init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS settings 
                 (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    conn.close()

def get_setting(key):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        print(f"Settings DB Error: {e}")
        return None

def save_setting(key, value):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Settings Save Error: {e}")

# --- NETWORK HELPERS ---
def get_server_ip():
    """Detects the primary IP of the server to avoid using localhost."""
    try:
        # Connect to a public endpoint to determine the route/source IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_target_service():
    """Returns the configured target IP or defaults to detected IP."""
    user_ip = get_setting("cf_target_ip")
    if user_ip and user_ip.strip():
        return f"http://{user_ip}:80"
    return f"http://{get_server_ip()}:80"

# --- CLOUDFLARE API HELPERS ---

def get_account_id(email, key):
    headers = {"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"}
    try:
        r = requests.get("https://api.cloudflare.com/client/v4/accounts", headers=headers, timeout=5)
        if r.status_code == 200:
            res = r.json().get('result', [])
            if res: return res[0]['id']
    except: pass
    return None

def get_cf_zone_id(domain, email, key):
    headers = {"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"}
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        search_domain = ".".join(parts[i:])
        try:
            r = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={search_domain}&status=active", headers=headers, timeout=5)
            if r.status_code == 200:
                for zone in r.json().get('result', []):
                    if zone['name'] == search_domain: 
                        return zone['id']
        except: pass
    return None

def add_cf_dns_record(domain, tunnel_id, email, key):
    zone_id = get_cf_zone_id(domain, email, key)
    if not zone_id: return False
    
    headers = {"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"}
    target = f"{tunnel_id}.cfargotunnel.com"
    data = {"type": "CNAME", "name": domain, "content": target, "proxied": True, "comment": "Managed by WordOps Panel"}
    
    try:
        r = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={domain}", headers=headers)
        existing = r.json().get('result', [])
        if existing:
            requests.put(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{existing[0]['id']}", headers=headers, json=data)
        else:
            requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers, json=data)
        return True
    except: return False

# --- TUNNEL MANAGEMENT STRATEGIES ---

def update_local_tunnel_config(new_domain):
    config_path = "/etc/cloudflared/config.yml"
    config = {"ingress": [{"service": "http_status:404"}]}
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            try:
                loaded = yaml.safe_load(f)
                if loaded: config = loaded
            except: pass

    if "ingress" not in config: config["ingress"] = [{"service": "http_status:404"}]
    
    if not any(r.get("hostname") == new_domain for r in config["ingress"]):
        idx = max(0, len(config["ingress"]) - 1)
        # Use dynamic target service (IP)
        config["ingress"].insert(idx, {"hostname": new_domain, "service": get_target_service()})
        
        with open(config_path, 'w') as f: yaml.dump(config, f, default_flow_style=False)
        subprocess.run(["systemctl", "restart", "cloudflared"])
        print(f"DEBUG: Local config updated for {new_domain} -> {get_target_service()}")

def update_remote_tunnel_config(domain, tunnel_id, email, key):
    account_id = get_account_id(email, key)
    if not account_id: return False
    
    headers = {"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"}
    base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
    
    try:
        r = requests.get(base_url, headers=headers)
        config = r.json().get('result', {}).get('config', {})
        if not config: config = {"ingress": [{"service": "http_status:404"}]}
        
        ingress = config.get("ingress", [])
        if not any(r.get("hostname") == domain for r in ingress):
            idx = max(0, len(ingress) - 1)
            # Use dynamic target service (IP)
            ingress.insert(idx, {"hostname": domain, "service": get_target_service()})
            config["ingress"] = ingress
            
            requests.put(base_url, headers=headers, json={"config": config})
            print(f"DEBUG: Remote config updated for {domain} -> {get_target_service()}")
    except Exception as e:
        print(f"Remote Update Error: {e}")

# --- ASSET HELPERS ---
def get_vault_assets():
    assets = []
    for t in ["plugins", "themes"]:
        path = os.path.join(ASSET_DIR, t)
        if os.path.exists(path):
            for f in os.listdir(path):
                if f.endswith(".zip"): assets.append({"name": f, "slug": os.path.join(path, f), "type": t[:-1], "source": "vault"})
    return assets

def get_all_assets():
    return [{**p, "source": "repo"} for p in REPO_PLUGINS] + get_vault_assets()

# --- STARTUP ---
@app.on_event("startup")
def startup_event(): init_db()

# --- SECURITY ---
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token: raise HTTPException(status_code=401)
    try:
        payload = jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub"): raise HTTPException(status_code=401)
        return payload.get("sub")
    except: raise HTTPException(status_code=401)

@app.get("/auth/check")
async def check(request: Request):
    await get_current_user(request)
    return Response(status_code=200)

# --- HELPERS ---
def get_wo_sites():
    try:
        conn = sqlite3.connect('/var/lib/wo/dbase.db')
        cur = conn.cursor()
        cur.execute("SELECT sitename, site_type, is_ssl, created_on, php_version FROM sites")
        res = cur.fetchall()
        conn.close()
        return [{"domain": r[0], "type": r[1], "ssl": r[2], "created": r[3], "php": r[4] or "N/A"} for r in res]
    except: return []

def run_wo_create(domain: str, ptype: str, username: str, email: str, install_list: list, activate_list: list):
    global deployment_progress
    deployment_progress[domain] = {"percent": 10, "status": "Allocating Resources..."}
    
    cmd = ["/usr/local/bin/wo", "site", "create", domain, "--wp", f"--user={username}", f"--email={email}", "--letsencrypt"]
    if ptype == "fastcgi": cmd.append("--wpfc")
    elif ptype == "redis": cmd.append("--wpredis")
    subprocess.run(cmd, capture_output=True)
    
    # --- HYBRID TUNNEL LOGIC ---
    cf_email = get_setting("cf_email")
    cf_key = get_setting("cf_key")
    tunnel_id = get_setting("cf_tunnel_id")
    tunnel_mode = get_setting("cf_tunnel_mode")
    
    if cf_email and cf_key and tunnel_id:
        deployment_progress[domain] = {"percent": 40, "status": "Configuring Tunnel..."}
        
        if tunnel_mode == 'local':
            update_local_tunnel_config(domain)
        else:
            update_remote_tunnel_config(domain, tunnel_id, cf_email, cf_key)
            
        deployment_progress[domain] = {"percent": 45, "status": "Updating DNS..."}
        add_cf_dns_record(domain, tunnel_id, cf_email, cf_key)
    # ---------------------------

    deployment_progress[domain] = {"percent": 90, "status": "Finalizing..."}
    subprocess.run(["sudo", "-u", "www-data", "/usr/local/bin/wp", "--path=" + f"/var/www/{domain}/htdocs", "plugin", "install", "one-time-login", "--activate"], capture_output=True)
    deployment_progress[domain] = {"percent": 100, "status": "Complete!"}

# --- ROUTES ---
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request): return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row[0]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    token = create_access_token(data={"sub": username})
    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie("access_token")
    return resp

@app.post("/create-site")
async def create_site(request: Request, bg: BackgroundTasks, domain: str = Form(...), stack: str = Form(...), username: str = Form(...), email: str = Form(...), install: list[str] = Form([]), activate: list[str] = Form([]), user: str = Depends(get_current_user)):
    deployment_progress[domain] = {"percent": 0, "status": "Starting..."}
    bg.add_task(run_wo_create, domain, stack, username, email, install, activate)
    return templates.TemplateResponse("progress_fragment.html", {"request": request, "domain": domain, "percent": 0, "status": "Queued"})

@app.get("/progress/{domain}")
async def progress(request: Request, domain: str):
    data = deployment_progress.get(domain, {"percent": 0, "status": "Unknown"})
    if data["percent"] >= 100: return HTMLResponse('<div class="text-center p-6"><h3 class="text-green-600 font-bold">Deployed!</h3><a href="/" class="underline">Refresh</a></div>')
    return templates.TemplateResponse("progress_fragment.html", {"request": request, "domain": domain, **data})

@app.get("/settings/modal")
async def settings(request: Request):
    detected_ip = get_server_ip()
    return templates.TemplateResponse("settings_modal.html", {
        "request": request,
        "cf_email": get_setting("cf_email") or "",
        "cf_key": get_setting("cf_key") or "",
        "cf_tunnel_token": get_setting("cf_tunnel_token") or "",
        "cf_tunnel_id": get_setting("cf_tunnel_id") or "",
        "cf_tunnel_mode": get_setting("cf_tunnel_mode") or "remote",
        "cf_target_ip": get_setting("cf_target_ip") or "",
        "detected_ip": detected_ip
    })

@app.post("/settings/save")
async def save_settings(
    cf_email: str = Form(""), cf_key: str = Form(""),
    cf_tunnel_token: str = Form(""), cf_tunnel_id: str = Form(""),
    cf_target_ip: str = Form(""),
    action: str = Form("save")
):
    save_setting("cf_email", cf_email)
    save_setting("cf_key", cf_key)
    save_setting("cf_target_ip", cf_target_ip)
    
    # CASE 1: AUTO-CREATE LOCAL TUNNEL
    if action == "create_tunnel":
        acc_id = get_account_id(cf_email, cf_key)
        if not acc_id: return HTMLResponse('<div class="text-red-600">Error: Check API Key/Email</div>')
        
        headers = {"X-Auth-Email": cf_email, "X-Auth-Key": cf_key, "Content-Type": "application/json"}
        r = requests.post(f"https://api.cloudflare.com/client/v4/accounts/{acc_id}/cfd_tunnel", headers=headers, json={"name": "wordops-panel-local", "config_src": "local"})
        
        if r.status_code != 200: return HTMLResponse(f'<div class="text-red-600">Creation Failed: {r.text}</div>')
        
        data = r.json()['result']
        t_id, t_secret = data['id'], data['tunnel_secret']
        
        os.makedirs("/etc/cloudflared", exist_ok=True)
        with open("/etc/cloudflared/cert.json", "w") as f: json.dump({"AccountTag": acc_id, "TunnelSecret": t_secret, "TunnelID": t_id}, f)
        with open("/etc/cloudflared/config.yml", "w") as f: yaml.dump({"tunnel": t_id, "credentials-file": "/etc/cloudflared/cert.json", "ingress": [{"service": "http_status:404"}]}, f)
            
        subprocess.run(["cloudflared", "service", "uninstall"], capture_output=True)
        subprocess.run(["cloudflared", "service", "install"], capture_output=True)
        subprocess.run(["systemctl", "restart", "cloudflared"], capture_output=True)
        
        save_setting("cf_tunnel_id", t_id)
        save_setting("cf_tunnel_mode", "local")
        save_setting("cf_tunnel_token", "")
        
        return HTMLResponse('<div class="text-green-600 font-bold">Tunnel Created (Local Mode)!</div>')

    # CASE 2: MANUAL TOKEN (REMOTE)
    if cf_tunnel_token:
        save_setting("cf_tunnel_token", cf_tunnel_token)
        save_setting("cf_tunnel_id", cf_tunnel_id)
        save_setting("cf_tunnel_mode", "remote")
        
        subprocess.run(["cloudflared", "service", "uninstall"], capture_output=True)
        subprocess.run(["cloudflared", "service", "install", cf_tunnel_token], capture_output=True)
        subprocess.run(["systemctl", "restart", "cloudflared"], capture_output=True)
        
        return HTMLResponse('<div class="text-green-600 font-bold">Token Saved (Remote Mode)!</div>')

    return HTMLResponse('<div class="text-green-600">Settings Saved.</div>')

# ... (Rest of User/Asset/Dashboard routes same as before) ...
@app.post("/users/add")
async def create_user_route(username: str = Form(...), password: str = Form(...), user: str = Depends(get_current_user)):
    if add_user(username, password): return HTMLResponse(f"<li>{username} <span class='text-green-600'>Added!</span></li>")
    return HTMLResponse("<li class='text-red-600'>Exists</li>")

@app.delete("/users/{username}")
async def delete_user_route(username: str, user: str = Depends(get_current_user)):
    delete_user(username)
    return HTMLResponse("") 

@app.post("/assets/upload")
async def upload_asset(file: UploadFile = File(...), type: str = Form(...), user: str = Depends(get_current_user)):
    if type not in ["plugins", "themes"]: return HTMLResponse("Invalid type", status_code=400)
    target_dir = os.path.join(ASSET_DIR, type)
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, file.filename), "wb") as f: shutil.copyfileobj(file.file, f)
    return templates.TemplateResponse("asset_list_fragment.html", {"request": {}, "assets": get_vault_assets()})

@app.delete("/assets/delete")
async def delete_asset(request: Request, path: str = Form(...), user: str = Depends(get_current_user)):
    if path.startswith(ASSET_DIR) and ".." not in path and os.path.exists(path): os.remove(path)
    return templates.TemplateResponse("asset_list_fragment.html", {"request": request, "assets": get_vault_assets()})

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {
        "request": request, "sites": get_wo_sites(), "user": user, 
        "admin_users": list_users(), "all_assets": get_all_assets(), "assets": get_vault_assets()
    })

@app.delete("/site/{domain}/delete")
def delete_site(domain: str, user: str = Depends(get_current_user)):
    result = subprocess.run(["/usr/local/bin/wo", "site", "delete", domain, "--no-prompt"], capture_output=True, text=True)
    if result.returncode == 0:
        return HTMLResponse(f'<tr class="bg-red-50"><td colspan="5" class="px-5 py-5 text-center text-red-600 font-bold">DOMAIN {domain} DELETED</td></tr>')
    return HTMLResponse(f'<tr class="bg-yellow-50"><td colspan="5" class="px-5 py-5 text-center text-yellow-700">Delete Failed: {result.stderr}</td></tr>')

@app.get("/site/{domain}/autologin")
async def autologin_site(domain: str):
    wp_base = ["sudo", "-u", "www-data", "/usr/local/bin/wp", "--path=" + f"/var/www/{domain}/htdocs"]
    if subprocess.run(wp_base + ["plugin", "is-installed", "one-time-login"], capture_output=True).returncode != 0:
        subprocess.run(wp_base + ["plugin", "install", "one-time-login", "--activate"], capture_output=True)
    user_res = subprocess.run(wp_base + ["user", "list", "--role=administrator", "--field=user_login", "--number=1"], capture_output=True, text=True)
    if not user_res.stdout.strip(): return HTMLResponse("No admin found")
    link = subprocess.run(wp_base + ["user", "one-time-login", user_res.stdout.strip(), "--porcelain"], capture_output=True, text=True)
    return RedirectResponse(url=link.stdout.strip())

@app.post("/site/{domain}/ssl")
async def enable_ssl(domain: str):
    cf_email, cf_key = get_setting("cf_email"), get_setting("cf_key")
    cmd = ["/usr/local/bin/wo", "site", "update", domain]
    env = os.environ.copy()
    if cf_email and cf_key:
        env["CF_Email"], env["CF_Key"] = cf_email, cf_key
        cmd.extend(["--le", "--dns=dns_cf"])
    else:
        cmd.append("--le")
    
    if subprocess.run(cmd, env=env, capture_output=True).returncode == 0:
        return HTMLResponse('<span class="text-green-500 font-bold text-xs border border-green-200 bg-green-50 px-2 py-1 rounded">SECURE</span>')
    return HTMLResponse('<button class="text-red-500 font-bold text-xs">Failed</button>')

@app.get("/site/{domain}/check-ssl")
async def check_ssl_status(domain: str):
    site = next((s for s in get_wo_sites() if s["domain"] == domain), None)
    if site and site["ssl"]: return HTMLResponse('<span class="text-green-500 font-bold text-xs border border-green-200 bg-green-50 px-2 py-1 rounded">SECURE</span>')
    try:
        if requests.head(f"https://{domain}", timeout=2).status_code < 500:
            return HTMLResponse('<span class="text-blue-500 font-bold text-xs border border-blue-200 bg-blue-50 px-2 py-1 rounded">SECURE (Proxy)</span>')
    except: pass
    return HTMLResponse(f'<button hx-post="/site/{domain}/ssl" hx-swap="outerHTML" class="text-orange-600 font-bold text-xs border border-orange-200 px-3 py-1 rounded">Encrypt</button>')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)