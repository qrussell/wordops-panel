import subprocess
import sqlite3
import os
import shutil
import requests
import yaml
import json
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
    """Initializes Users and Settings tables."""
    # Run the original auth init (creates users table)
    auth_init_db()
    
    # Initialize Settings Table
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS settings 
                 (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    conn.close()

def get_setting(key):
    """Retrieves a value from the settings table."""
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
    """Saves or updates a value in the settings table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Settings Save Error: {e}")

# --- CLOUDFLARE HELPER FUNCTIONS ---
def get_cf_zone_id(domain, email, key):
    """Finds the Zone ID for a given domain using Cloudflare API."""
    parts = domain.split('.')
    root_domain = ".".join(parts[-2:]) # Simple logic: "sub.example.com" -> "example.com"
    
    headers = {"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"}
    try:
        r = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={root_domain}", headers=headers, timeout=5)
        if r.status_code == 200 and len(r.json().get('result', [])) > 0:
            return r.json()['result'][0]['id']
    except Exception as e:
        print(f"CF API Error: {e}")
    return None

def add_cf_dns_record(domain, tunnel_id, email, key):
    """Adds a CNAME record pointing the domain to the Tunnel."""
    zone_id = get_cf_zone_id(domain, email, key)
    if not zone_id:
        print(f"Error: Could not find Zone ID for {domain}")
        return False

    headers = {"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"}
    target = f"{tunnel_id}.cfargotunnel.com"
    
    data = {
        "type": "CNAME",
        "name": domain,
        "content": target,
        "proxied": True, # Orange Cloud
        "comment": "Managed by WordOps Panel"
    }
    
    try:
        # Check if record exists
        r = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={domain}", headers=headers)
        existing = r.json().get('result', [])
        
        if existing:
            record_id = existing[0]['id']
            requests.put(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}", headers=headers, json=data)
        else:
            requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers, json=data)
        return True
    except Exception as e:
        print(f"DNS Record Error: {e}")
        return False

def update_tunnel_config(new_domain):
    """Adds a new ingress rule to /etc/cloudflared/config.yml"""
    config_path = "/etc/cloudflared/config.yml"
    
    # Default structure
    config = {"ingress": [{"service": "http_status:404"}]}
    
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            try:
                config = yaml.safe_load(f) or config
            except:
                pass

    if "ingress" not in config:
        config["ingress"] = [{"service": "http_status:404"}]

    # Check if domain exists
    exists = any(rule.get("hostname") == new_domain for rule in config["ingress"])
    
    if not exists:
        new_rule = {
            "hostname": new_domain,
            "service": "http://localhost:80"
        }
        # Insert before the catch-all (last item)
        config["ingress"].insert(0, new_rule)
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            # Restart Tunnel
            subprocess.run(["systemctl", "restart", "cloudflared"])
        except Exception as e:
            print(f"Tunnel Config Error: {e}")

# --- ASSET HELPERS ---
def get_vault_assets():
    """Scans the asset directories and returns a list of files."""
    assets = []
    
    p_path = os.path.join(ASSET_DIR, "plugins")
    if os.path.exists(p_path):
        for f in os.listdir(p_path):
            if f.endswith(".zip"):
                assets.append({"name": f, "slug": os.path.join(p_path, f), "type": "plugin", "source": "vault"})

    t_path = os.path.join(ASSET_DIR, "themes")
    if os.path.exists(t_path):
        for f in os.listdir(t_path):
            if f.endswith(".zip"):
                assets.append({"name": f, "slug": os.path.join(t_path, f), "type": "theme", "source": "vault"})
    
    return assets

def get_all_assets():
    repo_assets = [{**p, "source": "repo"} for p in REPO_PLUGINS]
    return repo_assets + get_vault_assets()

# --- STARTUP ---
@app.on_event("startup")
def startup_event():
    # Initialize DB (Users + Settings) on boot
    init_db()

# --- SECURITY DEPENDENCY ---
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    try:
        scheme, _, param = token.partition(" ")
        payload = jwt.decode(param, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

@app.exception_handler(HTTPException)
async def auth_exception_handler(request, exc):
    if exc.status_code == 401:
        return RedirectResponse(url="/login")
    return HTMLResponse(content=f"Error: {exc.detail}", status_code=exc.status_code)

@app.get("/auth/check")
async def nginx_auth_check(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    try:
        scheme, _, param = token.partition(" ")
        payload = jwt.decode(param, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return Response(status_code=status.HTTP_200_OK)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

# --- HELPERS (WordOps) ---
def get_wo_sites():
    try:
        conn = sqlite3.connect('/var/lib/wo/dbase.db')
        cursor = conn.cursor()
        cursor.execute("SELECT sitename, site_type, is_ssl, created_on, php_version FROM sites")
        sites = cursor.fetchall()
        conn.close()
        return [
            {
                "domain": s[0], 
                "type": s[1], 
                "ssl": s[2], 
                "created": s[3],
                "php": s[4] if s[4] else "N/A"
            } 
            for s in sites
        ]
    except Exception as e:
        print(f"DB Error: {e}")
        return []

def run_wo_create(domain: str, ptype: str, username: str, email: str, install_list: list, activate_list: list):
    global deployment_progress
    
    deployment_progress[domain] = {"percent": 10, "status": "Allocating Resources..."}
    deployment_progress[domain] = {"percent": 20, "status": "Running WordOps Create..."}
    
    cmd = ["/usr/local/bin/wo", "site", "create", domain, "--wp", f"--user={username}", f"--email={email}", "--letsencrypt"]
    if ptype == "fastcgi": cmd.append("--wpfc")
    elif ptype == "redis": cmd.append("--wpredis")
    
    subprocess.run(cmd, capture_output=True)
    
    # --- NEW: Cloudflare Tunnel Automation ---
    cf_email = get_setting("cf_email")
    cf_key = get_setting("cf_key")
    tunnel_token = get_setting("cf_tunnel_token")
    tunnel_id = get_setting("cf_tunnel_id")
    
    if cf_email and cf_key and tunnel_token and tunnel_id:
        deployment_progress[domain] = {"percent": 40, "status": "Configuring Cloudflare Tunnel..."}
        update_tunnel_config(domain)
        
        deployment_progress[domain] = {"percent": 45, "status": "Updating DNS Records..."}
        add_cf_dns_record(domain, tunnel_id, cf_email, cf_key)
    # -----------------------------------------

    deployment_progress[domain] = {"percent": 50, "status": "Configuring WP-CLI..."}
    site_path = f"/var/www/{domain}/htdocs"
    wp_base = ["sudo", "-u", "www-data", "/usr/local/bin/wp", "--path=" + site_path]

    clean_install_list = [p for p in install_list if p]
    total_assets = len(clean_install_list)
    
    if total_assets > 0:
        deployment_progress[domain] = {"percent": 60, "status": f"Installing {total_assets} assets..."}
        for i, asset_slug in enumerate(clean_install_list):
            step_progress = 60 + int((i / total_assets) * 30)
            deployment_progress[domain] = {"percent": step_progress, "status": f"Installing {asset_slug}..."}

            is_theme = "/themes/" in asset_slug and asset_slug.endswith(".zip")
            asset_type = "theme" if is_theme else "plugin"
            
            install_cmd = wp_base + [asset_type, "install", asset_slug]
            if asset_slug in activate_list:
                install_cmd.append("--activate")
            subprocess.run(install_cmd, capture_output=True)

    deployment_progress[domain] = {"percent": 95, "status": "Setting up Auto-Login..."}
    subprocess.run(wp_base + ["plugin", "install", "one-time-login", "--activate"], capture_output=True)
    
    deployment_progress[domain] = {"percent": 100, "status": "Deployment Complete!"}

# --- AUTH ROUTES ---
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if not row or not verify_password(password, row[0]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

    access_token = create_access_token(data={"sub": username})
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

# --- SITE ROUTES ---
@app.post("/create-site")
async def create_site(
    request: Request, background_tasks: BackgroundTasks, 
    domain: str = Form(...), stack: str = Form(...), 
    username: str = Form(...), email: str = Form(...),
    install: list[str] = Form([]), activate: list[str] = Form([]),
    user: str = Depends(get_current_user)
):
    deployment_progress[domain] = {"percent": 0, "status": "Queued"}
    background_tasks.add_task(run_wo_create, domain, stack, username, email, install, activate)
    return templates.TemplateResponse("progress_fragment.html", {
        "request": request, "domain": domain, "percent": 0, "status": "Starting..."
    })

@app.get("/progress/{domain}")
async def check_progress(request: Request, domain: str, user: str = Depends(get_current_user)):
    data = deployment_progress.get(domain, {"percent": 0, "status": "Unknown"})
    if data["percent"] >= 100:
        return HTMLResponse(f'''
            <div class="text-center p-6 space-y-4">
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                    <svg class="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                </div>
                <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white">Site Deployed Successfully!</h3>
                <div class="mt-5">
                    <a href="/" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-600 text-base font-medium text-white hover:bg-primary-700 focus:outline-none sm:text-sm">Refresh Dashboard</a>
                </div>
            </div>
        ''')
    return templates.TemplateResponse("progress_fragment.html", {
        "request": request, "domain": domain, "percent": data["percent"], "status": data["status"]
    })

@app.get("/site/{domain}", response_class=HTMLResponse)
async def get_site_modal(request: Request, domain: str, user: str = Depends(get_current_user)):
    return templates.TemplateResponse("modal.html", {"request": request, "domain": domain})

@app.delete("/site/{domain}/delete")
async def delete_site(domain: str, user: str = Depends(get_current_user)):
    subprocess.run(["/usr/local/bin/wo", "site", "delete", domain, "--no-prompt"], capture_output=True)
    return HTMLResponse(f'<div class="text-red-700 bg-red-100 p-4 rounded">Deleted {domain}</div>')

@app.get("/site/{domain}/autologin")
async def autologin_site(domain: str, user: str = Depends(get_current_user)):
    site_path = f"/var/www/{domain}/htdocs"
    wp_base = ["sudo", "-u", "www-data", "/usr/local/bin/wp", "--path=" + site_path]
    if subprocess.run(wp_base + ["plugin", "is-installed", "one-time-login"], capture_output=True).returncode != 0:
        subprocess.run(wp_base + ["plugin", "install", "one-time-login", "--activate"], capture_output=True)
    user_res = subprocess.run(wp_base + ["user", "list", "--role=administrator", "--field=user_login", "--number=1"], capture_output=True, text=True)
    if not user_res.stdout.strip(): return HTMLResponse("No admin found")
    link_res = subprocess.run(wp_base + ["user", "one-time-login", user_res.stdout.strip(), "--porcelain"], capture_output=True, text=True)
    return RedirectResponse(url=link_res.stdout.strip())

# --- SSL ROUTES (Cloudflare Integration) ---
@app.post("/site/{domain}/ssl")
async def enable_ssl(domain: str, user: str = Depends(get_current_user)):
    cf_email = get_setting("cf_email")
    cf_key = get_setting("cf_key")
    
    cmd = ["/usr/local/bin/wo", "site", "update", domain]
    env = os.environ.copy()

    if cf_email and cf_key:
        print(f"DEBUG: Using Cloudflare DNS for {domain}")
        env["CF_Email"] = cf_email
        env["CF_Key"] = cf_key
        cmd.append("--le")
        cmd.append("--dns=dns_cf")
    else:
        print(f"DEBUG: Using Standard HTTP Validation for {domain}")
        cmd.append("--le")

    result = subprocess.run(cmd, env=env, capture_output=True, text=True)

    if result.returncode == 0:
        return HTMLResponse('<span class="text-green-500 font-bold text-xs border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900 px-2 py-1 rounded select-none">SECURE</span>')
    else:
        print(f"SSL Error: {result.stderr}")
        return HTMLResponse(f'''
            <button class="text-red-500 text-xs font-bold border border-red-200 bg-red-50 px-2 py-1 rounded cursor-not-allowed" disabled title="Check Logs">Failed (Retry?)</button>
        ''')

@app.get("/site/{domain}/check-ssl")
async def check_ssl_status(domain: str, user: str = Depends(get_current_user)):
    sites = get_wo_sites()
    site = next((s for s in sites if s["domain"] == domain), None)
    
    if site and site["ssl"]:
        return HTMLResponse('<span class="text-green-500 font-bold text-xs border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900 px-2 py-1 rounded select-none" title="Secured by WordOps">SECURE</span>')

    try:
        r = requests.head(f"https://{domain}", timeout=2)
        if r.status_code < 500:
            return HTMLResponse('<span class="text-blue-500 font-bold text-xs border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900 px-2 py-1 rounded select-none" title="Secured by Proxy">SECURE (Proxy)</span>')
    except:
        pass

    return HTMLResponse(f'''
        <button hx-post="/site/{domain}/ssl" hx-swap="outerHTML" hx-indicator="#ssl-loading-{domain.replace('.', '-')}" class="group relative inline-flex items-center justify-center gap-1 text-orange-600 hover:text-white hover:bg-orange-500 border border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-gray-900 px-3 py-1 rounded text-xs font-bold transition-all duration-200 shadow-sm">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
            <span>Encrypt</span>
            <div id="ssl-loading-{domain.replace('.', '-')}" class="htmx-indicator absolute inset-0 bg-orange-500 rounded flex items-center justify-center">
                <svg class="w-4 h-4 text-white animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
            </div>
        </button>
    ''')

# --- SETTINGS ROUTES ---
@app.get("/settings/modal")
async def get_settings_modal(request: Request, user: str = Depends(get_current_user)):
    cf_email = get_setting("cf_email") or ""
    cf_key = get_setting("cf_key") or ""
    cf_tunnel_token = get_setting("cf_tunnel_token") or ""
    cf_tunnel_id = get_setting("cf_tunnel_id") or ""
    
    return templates.TemplateResponse("settings_modal.html", {
        "request": request,
        "cf_email": cf_email, 
        "cf_key": cf_key,
        "cf_tunnel_token": cf_tunnel_token,
        "cf_tunnel_id": cf_tunnel_id
    })

@app.post("/settings/save")
async def save_settings_route(
    cf_email: str = Form(""), 
    cf_key: str = Form(""),
    cf_tunnel_token: str = Form(""),
    cf_tunnel_id: str = Form(""),
    user: str = Depends(get_current_user)
):
    save_setting("cf_email", cf_email)
    save_setting("cf_key", cf_key)
    save_setting("cf_tunnel_token", cf_tunnel_token)
    save_setting("cf_tunnel_id", cf_tunnel_id)
    
    # Configure Cloudflare Tunnel Service if token is present
    if cf_tunnel_token:
        try:
            # Cleanup old
            subprocess.run(["cloudflared", "service", "uninstall"], capture_output=True)
            # Install new
            subprocess.run(["cloudflared", "service", "install", cf_tunnel_token], capture_output=True)
            # Start
            subprocess.run(["systemctl", "start", "cloudflared"], capture_output=True)
            
            # Ensure config.yml exists for management
            if not os.path.exists("/etc/cloudflared/config.yml"):
                initial_config = {
                    "tunnel": cf_tunnel_id,
                    "credentials-file": "/etc/cloudflared/cert.json", 
                    "ingress": [{"service": "http_status:404"}]
                }
                # Ensure dir exists
                os.makedirs("/etc/cloudflared", exist_ok=True)
                with open("/etc/cloudflared/config.yml", 'w') as f:
                    yaml.dump(initial_config, f)
        except Exception as e:
            print(f"Tunnel Install Error: {e}")
            return HTMLResponse(f'<div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4">Error: {e}</div>')

    return HTMLResponse('''
        <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 mb-4" role="alert">
            <p class="font-bold">Saved!</p>
            <p>Settings and Tunnel configuration updated.</p>
        </div>
    ''')

# --- USER MANAGER ROUTES ---
@app.post("/users/add")
async def create_user_route(username: str = Form(...), password: str = Form(...), user: str = Depends(get_current_user)):
    if add_user(username, password):
        return HTMLResponse(f"<li class='py-2 flex justify-between'><span>{username}</span> <span class='text-green-600'>Added! Refresh to manage.</span></li>")
    return HTMLResponse(f"<li class='text-red-600'>User {username} already exists.</li>")

@app.delete("/users/{username}")
async def delete_user_route(username: str, user: str = Depends(get_current_user)):
    delete_user(username)
    return HTMLResponse("") 

@app.post("/assets/upload")
async def upload_asset(file: UploadFile = File(...), type: str = Form(...), user: str = Depends(get_current_user)):
    if type not in ["plugins", "themes"]:
        return HTMLResponse('<li class="text-red-500">Error: Invalid asset type.</li>', status_code=400)
    target_dir = os.path.join(ASSET_DIR, type)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        os.chmod(target_dir, 0o775)
        shutil.chown(target_dir, user="www-data", group="www-data")
    file_path = os.path.join(target_dir, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        os.chmod(file_path, 0o664)
        shutil.chown(file_path, user="www-data", group="www-data")
    except Exception as e:
        return HTMLResponse(f'<li class="text-red-500">Error saving file: {str(e)}</li>', status_code=500)
    current_assets = get_vault_assets()
    return templates.TemplateResponse("asset_list_fragment.html", {"request": {}, "assets": current_assets})

@app.delete("/assets/delete")
async def delete_asset(request: Request, path: str = Form(...), user: str = Depends(get_current_user)):
    if not path.startswith(ASSET_DIR) or ".." in path:
         return HTMLResponse('<li class="text-red-500">Error: Invalid path.</li>', status_code=400)
    if os.path.exists(path):
        os.remove(path)
    return templates.TemplateResponse("asset_list_fragment.html", {"request": request, "assets": get_vault_assets()})

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "sites": get_wo_sites(), 
        "user": user, 
        "admin_users": list_users(),
        "all_assets": get_all_assets(),
        "assets": get_vault_assets()
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)