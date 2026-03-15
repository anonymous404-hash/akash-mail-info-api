from flask import Flask, request, jsonify
from datetime import datetime
import socket
import ssl
import whois
import dns.resolver
import requests
import os

app = Flask(__name__)

# --- API KEY DATABASE ---
# Format: "key_string": {"owner": "Name", "expiry": "YYYY-MM-DD"}
API_KEYS = {
    "AKASH-VIP-69": {"owner": "Premium User", "expiry": "2026-04-15"},
    "TEST-KEY-01": {"owner": "Trial User", "expiry": "2026-03-20"},
}

def check_key(key):
    if key not in API_KEYS:
        return False, "Invalid API Key. Please contact AKASH EXPLOITS."
    
    expiry_date = datetime.strptime(API_KEYS[key]["expiry"], "%YYYY-%m-%d")
    days_left = (expiry_date - datetime.now()).days
    
    if days_left < 0:
        return False, "API Key Expired. Renewal required."
    
    return True, days_left

@app.route('/')
def home():
    return jsonify({
        "status": "Active",
        "message": "Welcome to Mail Info Premium API",
        "usage": "/info?mail=example@gmail.com&key=YOUR_KEY",
        "developer": "AKASH EXPLOITS"
    })

@app.route('/info', methods=['GET'])
def mail_info():
    email = request.args.get('mail')
    user_key = request.args.get('key')

    if not user_key:
        return jsonify({"error": "API Key is missing"}), 403

    # --- KEY VALIDATION ---
    is_valid, result = check_key(user_key)
    if not is_valid:
        return jsonify({"error": result}), 403

    days_remaining = result

    if not email:
        return jsonify({"error": "Please provide ?mail= parameter"}), 400

    try:
        domain = email.split("@")[-1].strip().lower()

        # --- MX RECORDS ---
        try:
            mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX")]
        except Exception:
            mx_records = ["No record found"]

        # --- DOMAIN IP ---
        try:
            ip_addr = socket.gethostbyname(domain)
        except Exception:
            ip_addr = "Unknown"

        # --- WHOIS INFO ---
        try:
            w = whois.whois(domain)
            registrar = w.registrar or "Unknown"
            creation_date = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
        except Exception:
            registrar = creation_date = "Unknown"

        # --- ISP + LOCATION ---
        isp = "Unknown"
        location = "Unknown"
        if ip_addr != "Unknown":
            try:
                ipinfo = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=6).json()
                isp = ipinfo.get("isp", "Unknown")
                location = f"{ipinfo.get('city', 'Unknown')}, {ipinfo.get('country', 'Unknown')}"
            except Exception:
                pass

        # --- RESPONSE ---
        return jsonify({
            "Developer": "AKASH EXPLOITS",
            "Subscription_Status": {
                "Key_Owner": API_KEYS[user_key]["owner"],
                "Days_Remaining": f"{days_remaining} Days",
                "Expiry_Date": API_KEYS[user_key]["expiry"]
            },
            "Data": {
                "Email": email,
                "Domain": domain,
                "Provider": "Google Gmail" if "gmail" in domain else "Unknown",
                "MX_Records": mx_records,
                "Domain_IP": ip_addr,
                "Server_Location": location,
                "ISP": isp,
                "Registrar": registrar,
                "Creation_Date": creation_date
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

# CREDIT: @AKASH_EXPLOITS
