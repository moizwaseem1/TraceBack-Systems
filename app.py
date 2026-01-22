from flask import Flask, render_template, request, jsonify
import requests
import json
import concurrent.futures
import os

# ==========================================
# APP CONFIGURATION (Vercel-Safe)
# ==========================================
# We explicitly tell Flask where the folders are to avoid "404 Not Found" errors
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

# ==========================================
# PAGE ROUTES (Navigation)
# ==========================================

@app.route('/')
def index():
    return render_template('coming_soon.html')

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
