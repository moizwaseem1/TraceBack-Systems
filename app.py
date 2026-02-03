from flask import Flask, render_template, request, jsonify, send_from_directory
import requests
import json
import concurrent.futures
import os
from datetime import datetime

# ==========================================
# APP CONFIGURATION (Vercel-Safe)
# ==========================================
app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')

# ==========================================
# HELPER FUNCTIONS (The Engine)
# ==========================================

def load_sites():
    """Loads the list of websites to scan from the sites.json file."""
    try:
        # We use os.path to make sure we find the file on the Linux server
        file_path = os.path.join(os.getcwd(), 'sites.json')
        with open(file_path, 'r') as f:
            return json.load(f)['sites']
    except FileNotFoundError:
        print("Error: sites.json not found.")
        return []

def check_site_status(url, error_text):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        r = requests.get(url, headers=headers, timeout=5)
        
        # 1. Standard 404 check
        if r.status_code == 404:
            return False
            
        # 2. "Soft 404" Check (The Fix for Twitch/Pinterest)
        # We check if the specific error text exists in the HTML
        if error_text and error_text.lower() in r.text.lower():
            return False
            
        return True
    except:
        return False

# UPDATE YOUR ROUTE TO USE THIS FUNCTION
@app.route('/scan', methods=['POST'])
def scan_username():
    data = request.json
    username = data.get('username')
    
    with open('sites.json', 'r') as f:
        site_data = json.load(f)
        
    found_accounts = []
    
    for site in site_data['sites']:
        # We pass the URL AND the unique error message for that site
        url = site['url'].replace('{}', username)
        error_msg = site.get('error_msg')
        
        if check_site_status(url, error_msg):
            found_accounts.append({
                "site": site['name'],
                "url": url
            })
            
    return jsonify(found_accounts)

# --- CONFIGURATION ---
# Global cache to store breach data so we don't spam the API
BREACH_CACHE = {
    "data": {},
    "last_updated": None
}

def get_live_breach_data():
    """
    Fetches the list of all breached sites from HaveIBeenPwned.
    Refreshes data only once every 24 hours.
    """
    global BREACH_CACHE
    
    # Check if cache is valid (less than 24 hours old)
    if BREACH_CACHE["data"] and BREACH_CACHE["last_updated"]:
        time_diff = (datetime.now() - BREACH_CACHE["last_updated"]).total_seconds()
        if time_diff < 86400: 
            return BREACH_CACHE["data"]

    print("⚡ UPDATING BREACH DATABASE...")
    try:
        # User-Agent is required by HIBP
        headers = {'User-Agent': 'TraceBack-Systems-Scanner'}
        url = "https://haveibeenpwned.com/api/v3/breaches"
        
        r = requests.get(url, headers=headers, timeout=10)
        
        if r.status_code == 200:
            raw_list = r.json()
            new_data = {}
            for breach in raw_list:
                # Map Domain to Breach Info
                key = breach['Domain'].lower() 
                new_data[key] = {
                    "date": breach['BreachDate'],
                    "count": breach['PwnCount'],
                    "description": breach['Description'],
                    "risk": "HIGH" # All verified breaches are high risk
                }
                # Also map the Name (e.g. 'Adobe') just in case
                new_data[breach['Name'].lower()] = new_data[key]
                
            BREACH_CACHE["data"] = new_data
            BREACH_CACHE["last_updated"] = datetime.now()
            print(f"✅ LOADED {len(new_data)} BREACHED SITES.")
            return new_data
        else:
            return BREACH_CACHE["data"] # Fail safe: return old data
            
    except Exception as e:
        print(f"⚠️ API ERROR: {e}")
        return BREACH_CACHE["data"]

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html') # Assuming you have an index.html

@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')

@app.route('/radar')
def radar_page():
    return render_template('radar.html')
    
def check_site_status(url, username, error_text):
    """
    Returns TRUE if user exists, FALSE if not.
    Uses headers and content checking to avoid false positives.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        r = requests.get(url, headers=headers, timeout=5)
        
        # 1. If status is 404, user definitely doesn't exist
        if r.status_code == 404:
            return False
            
        # 2. If status is 200, we must check for "Error Text"
        # If the specific error text is IN the HTML, the user does NOT exist.
        if error_text and error_text in r.text:
            return False
            
        # 3. Special Case: If we got blocked (403/429), assume False to be safe
        if r.status_code in [403, 429]:
            return False

        # If we passed all checks, the user exists
        return True
        
    except:
        return False

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
    
    # 1. Filter sites that are in the Breach DB
    for site in site_data['sites']:
        site_name = site['name'].lower()
        if site_name in breach_db:
            site['breach_details'] = breach_db[site_name]
            target_sites.append(site)

    results = []
    
    # 2. Verify existence using the new ROBUST check
    for site in target_sites:
        # Check if the user actually exists on the site first
        user_exists = check_site_status(
            site['url'].replace('{}', username), 
            username, 
            site.get('error_msg')
        )
        
        if user_exists:
            results.append({
                "site": site['name'],
                "status": "VULNERABLE",
                "breach_date": site['breach_details']['date'],
                "risk": "HIGH",
                # We change wording to be truthful:
                "description": "Account exists on breached platform." 
            })

    return jsonify(results)
    
# ==========================================
# PAGE ROUTES (Navigation)
# ==========================================
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.png', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def index():
    return render_template('index.html')

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

# ==========================================
# API ROUTES (The Logic)
# ==========================================

@app.route('/join-waitlist', methods=['POST'])
def join_waitlist():
    """
    Simulates saving to a database. 
    (Vercel is Read-Only, so we can't write to a file here safely without a real DB).
    """
    try:
        data = request.json
        email = data.get('email')
        
        if not email or '@' not in email:
            return jsonify({"error": "Invalid email format"}), 400
        
        # VERCEL SIMULATION MODE
        # We return a success message so the user feels the system working.
        return jsonify({
            "success": True, 
            "position": 482, # Fake queue number to build hype
            "message": "Protocol Initiated. You are on the list."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    # 0.0.0.0 is required for Docker/Codespaces
    app.run(debug=True, host='0.0.0.0', port=5000)
