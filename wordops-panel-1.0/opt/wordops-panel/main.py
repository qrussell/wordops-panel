import subprocess
import sqlite3
import os
import shutil
from fastapi import UploadFile, File
from fastapi import FastAPI, Request, Form, BackgroundTasks, Depends, HTTPException, status, Response
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt, JWTError

# Import our custom Auth module
from auth import (
    init_user_db, verify_password, create_access_token, 
    list_users, add_user, delete_user, 
    SECRET_KEY, ALGORITHM
)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- CONFIGURATION ---
ASSET_DIR = "/var/lib/wordops-panel/assets"
REPO_PLUGINS = [
    {"name": "Elementor", "slug": "elementor", "type": "plugin"},
    {"name": "Yoast SEO", "slug": "wordpress-seo", "type": "plugin"},
    {"name": "WooCommerce", "slug": "woocommerce", "type": "plugin"},
    {"name": "Wordfence", "slug": "wordfence", "type": "plugin"},
    {"name": "Classic Editor", "slug": "classic-editor", "type": "plugin"},
]
# --- GLOBAL STATE ---
# Stores progress for active deployments: { "example.com": {"percent": 0, "status": "Pending"} }
deployment_progress = {}
# --- ASSET HELPERS ---
def get_vault_assets():
    """Scans the asset directories and returns a list of files."""
    assets = []
    print(f"DEBUG: Scanning {ASSET_DIR}...") # Debug print
    
    # Scan Plugins
    p_path = os.path.join(ASSET_DIR, "plugins")
    if os.path.exists(p_path):
        for f in os.listdir(p_path):
            if f.endswith(".zip"):
                print(f"DEBUG: Found plugin {f}") # Debug print
                assets.append({"name": f, "slug": os.path.join(p_path, f), "type": "plugin", "source": "vault"})
    else:
        print(f"DEBUG: Plugin path {p_path} does not exist") # Debug print

    # Scan Themes
    t_path = os.path.join(ASSET_DIR, "themes")
    if os.path.exists(t_path):
        for f in os.listdir(t_path):
            if f.endswith(".zip"):
                print(f"DEBUG: Found theme {f}") # Debug print
                assets.append({"name": f, "slug": os.path.join(t_path, f), "type": "theme", "source": "vault"})
    
    return assets

def get_all_assets():
    """Combines Repo plugins and Vault assets for the deployment list."""
    # Mark repo plugins with source='repo' for UI distinction
    repo_assets = [{**p, "source": "repo"} for p in REPO_PLUGINS]
    return repo_assets + get_vault_assets()
	
# --- STARTUP ---
@app.on_event("startup")
def startup_event():
    # Initialize the User DB on boot
    init_user_db()

# --- SECURITY DEPENDENCY ---
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    try:
        # Token format: "Bearer <token>"
        scheme, _, param = token.partition(" ")
        payload = jwt.decode(param, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

# Redirect 401 errors to Login Page automatically
@app.exception_handler(HTTPException)
async def auth_exception_handler(request, exc):
    if exc.status_code == 401:
        return RedirectResponse(url="/login")
    return HTMLResponse(content=f"Error: {exc.detail}", status_code=exc.status_code)

# --- HELPERS (WordOps) ---
def get_wo_sites():
    try:
        conn = sqlite3.connect('/var/lib/wo/dbase.db')
        cursor = conn.cursor()
        cursor.execute("SELECT sitename, site_type, is_ssl, created_on FROM sites")
        sites = cursor.fetchall()
        conn.close()
        return [{"domain": s[0], "type": s[1], "ssl": s[2], "created": s[3]} for s in sites]
    except Exception as e:
        print(f"DB Error: {e}")
        return []

def run_wo_create(domain: str, ptype: str, username: str, email: str, install_list: list, activate_list: list):
    global deployment_progress
    
    # 1. Start
    deployment_progress[domain] = {"percent": 10, "status": "Allocating Resources..."}
    
    # 2. Create Site (The longest step)
    deployment_progress[domain] = {"percent": 20, "status": "Running WordOps Create (This takes time)..."}
    
    cmd = ["/usr/local/bin/wo", "site", "create", domain, "--wp", f"--user={username}", f"--email={email}", "--letsencrypt"]
    if ptype == "fastcgi": cmd.append("--wpfc")
    elif ptype == "redis": cmd.append("--wpredis")
    
    # Run creation
    subprocess.run(cmd, capture_output=True)
    
    # 3. Setup WP-CLI
    deployment_progress[domain] = {"percent": 50, "status": "Configuring WP-CLI..."}
    site_path = f"/var/www/{domain}/htdocs"
    wp_base = ["sudo", "-u", "www-data", "/usr/local/bin/wp", "--path=" + site_path]

    # 4. Install Assets
    clean_install_list = [p for p in install_list if p]
    total_assets = len(clean_install_list)
    
    if total_assets > 0:
        deployment_progress[domain] = {"percent": 60, "status": f"Installing {total_assets} assets..."}
        
        for i, asset_slug in enumerate(clean_install_list):
            # Calculate granular progress for assets (60% to 90%)
            step_progress = 60 + int((i / total_assets) * 30)
            deployment_progress[domain] = {"percent": step_progress, "status": f"Installing {asset_slug}..."}

            is_theme = "/themes/" in asset_slug and asset_slug.endswith(".zip")
            asset_type = "theme" if is_theme else "plugin"
            
            install_cmd = wp_base + [asset_type, "install", asset_slug]
            if asset_slug in activate_list:
                install_cmd.append("--activate")
                
            subprocess.run(install_cmd, capture_output=True)

    # 5. Finalize
    deployment_progress[domain] = {"percent": 95, "status": "Setting up Auto-Login..."}
    subprocess.run(wp_base + ["plugin", "install", "one-time-login", "--activate"], capture_output=True)
    
    # 6. Done
    deployment_progress[domain] = {"percent": 100, "status": "Deployment Complete!"}

# --- AUTH ROUTES ---
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    # Verify against DB
    conn = sqlite3.connect("/var/lib/wo/wordops-panel_users.db")
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if not row or not verify_password(password, row[0]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

    # Success: Create Token & Cookie
    access_token = create_access_token(data={"sub": username})
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

@app.post("/create-site")
async def create_site(
    request: Request, background_tasks: BackgroundTasks, 
    domain: str = Form(...), stack: str = Form(...), 
    username: str = Form(...), email: str = Form(...),
    install: list[str] = Form([]), activate: list[str] = Form([]),
    user: str = Depends(get_current_user)
):
    # Initialize Progress
    deployment_progress[domain] = {"percent": 0, "status": "Queued"}
    
    # Start Task
    background_tasks.add_task(run_wo_create, domain, stack, username, email, install, activate)
    
    # Return the Progress Bar immediately (Poller)
    return templates.TemplateResponse("progress_fragment.html", {
        "request": request, 
        "domain": domain, 
        "percent": 0, 
        "status": "Starting..."
    })

@app.get("/progress/{domain}")
async def check_progress(request: Request, domain: str, user: str = Depends(get_current_user)):
    data = deployment_progress.get(domain, {"percent": 0, "status": "Unknown"})
    
    # If complete, send a different UI (Success Button)
    if data["percent"] >= 100:
        return HTMLResponse(f'''
            <div class="text-center p-6 space-y-4">
                <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                    <svg class="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                </div>
                <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white">Site Deployed Successfully!</h3>
                <div class="mt-2">
                    <p class="text-sm text-gray-500 dark:text-gray-400">
                        {domain} is now live and ready.
                    </p>
                </div>
                <div class="mt-5">
                    <a href="/" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-600 text-base font-medium text-white hover:bg-primary-700 focus:outline-none sm:text-sm">
                        Refresh Dashboard
                    </a>
                </div>
            </div>
        ''')

    # Otherwise, return the updated progress bar (Polling continues)
    return templates.TemplateResponse("progress_fragment.html", {
        "request": request, 
        "domain": domain, 
        "percent": data["percent"], 
        "status": data["status"]
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
    # ... (Your existing Autologin logic here - shortened for brevity, but keep your robust version!) ...
    # Note: Copy your Robust WP-CLI Autologin function from previous steps here
    site_path = f"/var/www/{domain}/htdocs"
    wp_base = ["sudo", "-u", "www-data", "/usr/local/bin/wp", "--path=" + site_path]
    
    # Check plugin
    if subprocess.run(wp_base + ["plugin", "is-installed", "one-time-login"], capture_output=True).returncode != 0:
        subprocess.run(wp_base + ["plugin", "install", "one-time-login", "--activate"], capture_output=True)

    # Get User
    user_res = subprocess.run(wp_base + ["user", "list", "--role=administrator", "--field=user_login", "--number=1"], capture_output=True, text=True)
    if not user_res.stdout.strip(): return HTMLResponse("No admin found")
    
    # Get Link
    link_res = subprocess.run(wp_base + ["user", "one-time-login", user_res.stdout.strip(), "--porcelain"], capture_output=True, text=True)
    return RedirectResponse(url=link_res.stdout.strip())

@app.post("/site/{domain}/ssl")
async def enable_ssl(domain: str, user: str = Depends(get_current_user)):
    # Run WordOps command: wo site update domain.com --le
    # --le tells WordOps to issue a Let's Encrypt certificate
    cmd = ["/usr/local/bin/wo", "site", "update", domain, "--le"]
    
    # Run command and capture output
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        # Success: Return the standard Green Secure Badge
        return HTMLResponse('<span class="text-green-500 font-bold text-xs border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900 px-2 py-1 rounded">SECURE</span>')
    else:
        # Failure: Return an error message button (allows retry)
        return HTMLResponse(f'''
            <button class="text-red-500 text-xs font-bold border border-red-200 bg-red-50 px-2 py-1 rounded cursor-not-allowed" disabled title="Check server logs">
                Failed (Retry?)
            </button>
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
    return HTMLResponse("") # Remove element from DOM
	
@app.post("/assets/upload")
async def upload_asset(
    file: UploadFile = File(...), 
    type: str = Form(...), 
    user: str = Depends(get_current_user)
):
    # 1. Security Check: Only allow 'plugins' or 'themes'
    if type not in ["plugins", "themes"]:
        return HTMLResponse('<li class="text-red-500">Error: Invalid asset type.</li>', status_code=400)
    
    # 2. Security Check: Ensure directory exists
    target_dir = os.path.join(ASSET_DIR, type)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        # Fix permissions so www-data can read it later
        os.chmod(target_dir, 0o775)
        shutil.chown(target_dir, user="www-data", group="www-data")

    # 3. Save the File
    file_path = os.path.join(target_dir, file.filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Ensure the file itself is readable by www-data
        os.chmod(file_path, 0o664)
        shutil.chown(file_path, user="www-data", group="www-data")
        
    except Exception as e:
        return HTMLResponse(f'<li class="text-red-500">Error saving file: {str(e)}</li>', status_code=500)
        
    # 4. Return the updated list using the fragment
    # We re-fetch the list so the UI updates immediately
    current_assets = get_vault_assets()
    return templates.TemplateResponse("asset_list_fragment.html", {"request": {}, "assets": current_assets})

@app.delete("/assets/delete")
async def delete_asset(request: Request, path: str = Form(...), user: str = Depends(get_current_user)):
    # ... (rest of security check logic) ...
        
    return templates.TemplateResponse("asset_list_fragment.html", {
        "request": request,  # <--- ADD THIS
        "assets": get_vault_assets()
    })

# Update Dashboard to pass assets
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "sites": get_wo_sites(), 
        "user": user, 
        "admin_users": list_users(),
        "all_assets": get_all_assets(),    # For Deployment Modal
        "assets": get_vault_assets()       # <--- FIXED: Call the function directly
    })