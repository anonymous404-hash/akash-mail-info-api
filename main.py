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
    
    try:
        expiry_date = datetime.strptime(API_KEYS[key]["expiry"], "%Y-%m-%d")
        days_left = (expiry_date - datetime.now()).days
        
        if days_left < 0:
            return False, "API Key Expired. Renewal required."
        
        return True, days_left
    except Exception as e:
        return False, f"Error checking key: {str(e)}"

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

    # --- KEY VALIDATION ---
    if not user_key:
        return jsonify({"error": "API Key is missing"}), 403

    is_valid, result = check_key(user_key)
    if not is_valid:
        return jsonify({"error": result}), 403

    days_remaining = result

    if not email:
        return jsonify({"error": "Please provide ?mail= parameter"}), 400

    # Validate email format
    if '@' not in email or '.' not in email:
        return jsonify({"error": "Invalid email format"}), 400

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

        # --- SSL ISSUER ---
        ssl_issuer = "Unknown"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    ssl_issuer = issuer.get("organizationName", "Unknown")
        except Exception:
            pass

        # --- WHOIS INFO ---
        registrar = "Unknown"
        creation_date = "Unknown"
        expiration_date = "Unknown"
        try:
            w = whois.whois(domain)
            registrar = w.registrar or "Unknown"
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = str(w.creation_date[0])
                else:
                    creation_date = str(w.creation_date)
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = str(w.expiration_date[0])
                else:
                    expiration_date = str(w.expiration_date)
        except Exception:
            pass

        # --- ISP + LOCATION ---
        isp = "Unknown"
        location = "Unknown"
        if ip_addr != "Unknown":
            try:
                ipinfo = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=6).json()
                if ipinfo.get('status') == 'success':
                    isp = ipinfo.get("isp", "Unknown")
                    location = f"{ipinfo.get('city', 'Unknown')}, {ipinfo.get('country', 'Unknown')}"
            except Exception:
                pass

        # --- DISPOSABLE DOMAIN CHECK ---
        disposable_domains = [
            "tempmail.com", "10minutemail.com", "yopmail.com", 
            "guerrillamail.com", "mailinator.com", "temp-mail.org",
            "throwawaymail.com", "fakeinbox.com", "tempinbox.com"
        ]
        disposable = "Yes" if domain in disposable_domains else "No"

        # --- PROVIDER DETECTION ---
        provider = "Unknown"
        if "gmail.com" in domain:
            provider = "Google Gmail"
        elif "yahoo.com" in domain:
            provider = "Yahoo Mail"
        elif "outlook.com" in domain or "hotmail.com" in domain:
            provider = "Microsoft Outlook"
        elif "protonmail.com" in domain:
            provider = "ProtonMail"
        elif "zoho.com" in domain:
            provider = "Zoho Mail"
        elif "aol.com" in domain:
            provider = "AOL Mail"
        elif "mail.com" in domain:
            provider = "Mail.com"

        # --- BREACH CHECK ---
        breaches = []
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json",
                "api-version": "3"
            }
            hibp = requests.get(
                f"https://haveibeenpwned.com/unifiedsearch/{email}",
                headers=headers,
                timeout=10
            )
            if hibp.status_code == 200:
                data = hibp.json()
                breaches = [b["Name"] for b in data.get("Breaches", [])]
            elif hibp.status_code == 404:
                breaches = []
            else:
                breaches = ["Error fetching data"]
        except requests.exceptions.Timeout:
            breaches = ["Request timeout"]
        except Exception:
            breaches = ["Error fetching data"]

        # --- RESPONSE (Original structure maintained) ---
        response_data = {
            "Email": email,
            "Domain": domain,
            "Provider": provider,
            "MX Records": mx_records,
            "Domain IP": ip_addr,
            "Server Location": location,
            "ISP": isp,
            "Registrar": registrar,
            "Creation Date": creation_date,
            "Expiration Date": expiration_date,
            "SSL Issuer": ssl_issuer,
            "Disposable": disposable,
            "Breaches Found": breaches,
            "Developer": "AKASH EXPLOITS",
            "Subscription": {
                "Key_Owner": API_KEYS[user_key]["owner"],
                "Days_Remaining": f"{days_remaining} Days",
                "Expiry_Date": API_KEYS[user_key]["expiry"]
            }
        }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

# CREDIT: @AKASH_EXPLOITS
# Based on original by @SHHACKERDEV404
