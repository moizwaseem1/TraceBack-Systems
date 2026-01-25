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

def check_site(site, username):
    """
    Checks a single website.
    RETURNS: The result ONLY if the user is found (Status 200).
    """
    url = site['url'].format(username)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        # Timeout set to 5 seconds to keep the tool fast
        response = requests.get(url, headers=headers, timeout=5)
        
        # STRICT MODE: Only return if we get a solid 200 OK
        if response.status_code == 200:
            return {
                "site": site['name'],
                "url": url,
                "status": "FOUND",
                "color": "green"
            }
        else:
            # We return None so we can filter it out easily later
            return None
    except:
        return None

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

@app.route('/radar')
def radar_page():
    return render_template('radar.html')

@app.route('/scan-breach', methods=['POST'])
def scan_breach():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Target Required"}), 400

    # 1. Get Live Breach Data
    breach_db = get_live_breach_data()
    
    # 2. Load Supported Sites
    # Ensure 'sites.json' exists in your folder
    try:
        with open('sites.json', 'r') as f:
            site_data = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "System Error: sites.json missing"}), 500
    
    # 3. Filter: Only scan sites that are KNOWN to be breached
    target_sites = []
    for site in site_data['sites']:
        # Extract domain key (e.g., myspace.com -> myspace)
        try:
            domain_part = site['url'].split('/')[2].replace('www.', '').lower()
        except:
            domain_part = site['name'].lower()
            
        site_name = site['name'].lower()
        
        # Check if this site is in the breach database
        match = None
        if site_name in breach_db:
            match = breach_db[site_name]
        elif domain_part in breach_db:
            match = breach_db[domain_part]
            
        if match:
            site['breach_details'] = match
            target_sites.append(site)

    # 4. Perform the Scan (Check if user exists on these breached sites)
    results = []
    
    # Limit to first 10 matches for speed in this demo
    for site in target_sites[:10]:
        try:
            check_url = site['url'].replace('{}', username)
            # Fast timeout
            r = requests.get(check_url, timeout=3)
            
            # If status is 200, user exists -> VULNERABLE
            if r.status_code == 200:
                results.append({
                    "site": site['name'],
                    "status": "VULNERABLE",
                    "breach_date": site['breach_details']['date'],
                    "pwn_count": site['breach_details']['count'],
                    "risk": "CRITICAL"
                })
        except:
            continue

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

@app.route('/scan', methods=['POST'])
def scan():
    """
    Receives a username, scans 50+ sites in parallel, 
    and returns ONLY the found profiles.
    """
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify([])

    sites = load_sites()
    results = []
    
    # High-Performance Multi-threading
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_site = {executor.submit(check_site, site, username): site for site in sites}
        for future in concurrent.futures.as_completed(future_to_site):
            try:
                result = future.result()
                if result: # Only append if result is not None (i.e., User Found)
                    results.append(result)
            except Exception as e:
                continue
            
    return jsonify(results)

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
