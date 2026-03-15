from flask import Flask, request, jsonify
from datetime import datetime
import socket
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

    if not user_key:
        return jsonify({"error": "API Key is missing"}), 403

    # --- KEY VALIDATION ---
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
        mx_records = []
        try:
            mx_answers = dns.resolver.resolve(domain, "MX")
            mx_records = [str(r.exchange).rstrip('.') for r in mx_answers]
        except dns.resolver.NoAnswer:
            mx_records = ["No MX records found"]
        except dns.resolver.NXDOMAIN:
            mx_records = ["Domain does not exist"]
        except Exception as e:
            mx_records = [f"Error: {str(e)}"]

        # --- DOMAIN IP ---
        ip_addr = "Unknown"
        try:
            ip_addr = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_addr = "Could not resolve domain"
        except Exception:
            ip_addr = "Unknown"

        # --- WHOIS INFO ---
        registrar = "Unknown"
        creation_date = "Unknown"
        try:
            w = whois.whois(domain)
            registrar = w.registrar if w.registrar else "Unknown"
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = str(w.creation_date[0])
                else:
                    creation_date = str(w.creation_date)
            else:
                creation_date = "Unknown"
        except Exception:
            pass  # Keep default Unknown values

        # --- ISP + LOCATION ---
        isp = "Unknown"
        location = "Unknown"
        if ip_addr != "Unknown" and ip_addr != "Could not resolve domain":
            try:
                # Using ip-api.com (free, no API key required)
                ipinfo = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=5).json()
                if ipinfo.get('status') == 'success':
                    isp = ipinfo.get("isp", "Unknown")
                    location = f"{ipinfo.get('city', 'Unknown')}, {ipinfo.get('country', 'Unknown')}"
                else:
                    isp = "Location lookup failed"
                    location = "Location lookup failed"
            except requests.exceptions.Timeout:
                isp = "Location lookup timeout"
                location = "Location lookup timeout"
            except Exception:
                pass

        # Determine provider based on MX records
        provider = "Unknown"
        if any('google.com' in mx or 'googlemail.com' in mx for mx in mx_records):
            provider = "Google Gmail"
        elif any('outlook.com' in mx or 'hotmail.com' in mx for mx in mx_records):
            provider = "Microsoft Outlook"
        elif any('yahoo.com' in mx for mx in mx_records):
            provider = "Yahoo Mail"
        elif any('protonmail.com' in mx for mx in mx_records):
            provider = "ProtonMail"
        elif any('zoho.com' in mx for mx in mx_records):
            provider = "Zoho Mail"

        # --- RESPONSE ---
        return jsonify({
            "Developer": "AKASH EXPLOITS",
            "Subscription_Status": {
                "Key_Owner": API_KEYS[user_key]["owner"],
                "Days_Remaining": f"{days_remaining} Days" if days_remaining >= 0 else "Expired",
                "Expiry_Date": API_KEYS[user_key]["expiry"]
            },
            "Data": {
                "Email": email,
                "Domain": domain,
                "Provider": provider,
                "MX_Records": mx_records,
                "Domain_IP": ip_addr,
                "Server_Location": location,
                "ISP": isp,
                "Registrar": registrar,
                "Creation_Date": creation_date
            }
        })

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

# CREDIT: @AKASH_EXPLOITS
