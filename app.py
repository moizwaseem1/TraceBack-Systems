from flask import Flask, render_template, request, jsonify, send_from_directory
import requests
import json
import os
from datetime import datetime

# ==========================================
# APP CONFIGURATION
# ==========================================
app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')

# ==========================================
# HELPER FUNCTIONS (The Engine)
# ==========================================

# --- GLOBAL BREACH CACHE ---
BREACH_CACHE = {
    "data": {},
    "last_updated": None
}

def get_live_breach_data():
    """Fetches breach data from HIBP API with caching."""
    global BREACH_CACHE
    
    if BREACH_CACHE["data"] and BREACH_CACHE["last_updated"]:
        time_diff = (datetime.now() - BREACH_CACHE["last_updated"]).total_seconds()
        if time_diff < 86400: 
            return BREACH_CACHE["data"]

    print("⚡ UPDATING BREACH DATABASE...")
    try:
        headers = {'User-Agent': 'TraceBack-Systems-Scanner'}
        url = "https://haveibeenpwned.com/api/v3/breaches"
        r = requests.get(url, headers=headers, timeout=10)
        
        if r.status_code == 200:
            raw_list = r.json()
            new_data = {}
            for breach in raw_list:
                key = breach['Domain'].lower() 
                new_data[key] = {
                    "date": breach['BreachDate'],
                    "count": breach['PwnCount'],
                    "description": breach['Description'],
                    "risk": "HIGH"
                }
                new_data[breach['Name'].lower()] = new_data[key]
                
            BREACH_CACHE["data"] = new_data
            BREACH_CACHE["last_updated"] = datetime.now()
            return new_data
        else:
            return BREACH_CACHE["data"]
    except Exception as e:
        print(f"⚠️ API ERROR: {e}")
        return BREACH_CACHE["data"]

# --- REPLACE THIS FUNCTION IN APP.PY ---

# --- REPLACE THIS FUNCTION IN APP.PY ---

def check_site_status(url, error_text):
    """
    STRICT MODE: Filters out WAF blocks, Captchas, and Soft 404s.
    """
    headers = {
        # Using a standard Linux User-Agent to look less suspicious
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }
    try:
        # allow_redirects=True lets us see if we get bumped to a login page
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        
        # DEBUG: Print what we actually found (Check your Vercel logs for this!)
        # print(f"Checking {url} -> Status: {r.status_code} | Title: {r.text[:100]}")

        # 1. Hard 404 Check (The most reliable)
        if r.status_code == 404:
            return False
            
        # 2. WAF & Bot Detection Check (The Fix for "Fake" Results)
        # If the page title indicates a block, it is NOT a profile.
        page_text = r.text.lower()
        block_keywords = [
            "<title>access denied</title>",
            "<title>just a moment...</title>",
            "<title>security challenge</title>",
            "<title>attention required!</title>",
            "verify you are human",
            "captcha",
            "cloudflare",
            "incapsula"
        ]
        
        for keyword in block_keywords:
            if keyword in page_text:
                return False # We got blocked, so assume user not found to be safe

        # 3. "Soft 404" Check (Specific Site Errors)
        if error_text and error_text.lower() in page_text:
            return False
            
        # 4. Login Page Trap
        # If we got redirected to a login page, the profile is not public/doesn't exist
        if "login" in r.url or "signin" in r.url:
            return False
            
        return True
    except Exception as e:
        # print(f"Error checking {url}: {e}")
        return False

# ==========================================
# API ROUTES (Scanner Logic)
# ==========================================

@app.route('/scan', methods=['POST'])
def scan_username():
    data = request.json
    username = data.get('username')
    
    try:
        with open('sites.json', 'r') as f:
            site_data = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "sites.json missing"}), 500

    found_accounts = []
    
    for site in site_data['sites']:
        url = site['url'].replace('{}', username)
        error_msg = site.get('error_msg')
        
        # Correctly calling the function with 2 arguments
        if check_site_status(url, error_msg):
            found_accounts.append({
                "site": site['name'],
                "url": url
            })
            
    return jsonify(found_accounts)

@app.route('/scan-breach', methods=['POST'])
def scan_breach():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Target Required"}), 400

    breach_db = get_live_breach_data()
    
    try:
        with open('sites.json', 'r') as f:
            site_data = json.load(f)
    except:
        return jsonify([]), 500

    target_sites = []
    
    # Filter sites that are in the Breach DB
    for site in site_data['sites']:
        site_name = site['name'].lower()
        if site_name in breach_db:
            site['breach_details'] = breach_db[site_name]
            target_sites.append(site)

    results = []
    
    for site in target_sites:
        url = site['url'].replace('{}', username)
        error_msg = site.get('error_msg')

        # Correctly calling the function with 2 arguments
        if check_site_status(url, error_msg):
            results.append({
                "site": site['name'],
                "status": "VULNERABLE",
                "breach_date": site['breach_details']['date'],
                "risk": "HIGH",
                "description": "Account exists on breached platform."
            })

    return jsonify(results)

@app.route('/join-waitlist', methods=['POST'])
def join_waitlist():
    try:
        data = request.json
        email = data.get('email')
        
        if not email or '@' not in email:
            return jsonify({"error": "Invalid email format"}), 400
        
        return jsonify({
            "success": True, 
            "position": 482, 
            "message": "Protocol Initiated. You are on the list."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# PAGE ROUTES (Navigation)
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')

@app.route('/radar')
def radar_page():
    return render_template('radar.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/tools')
def tools():
    return render_template('tools.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.png', mimetype='image/vnd.microsoft.icon')

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
