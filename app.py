import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import threading
import time

from data_pb2 import AccountPersonalShowInfo
from google.protobuf.descriptor import FieldDescriptor
import uid_generator_pb2
import GetWishListItems_pb2 

# --- BASE64 DECODED DEVELOPER CREDENTIALS ---
# Encoded strings for tamper-resistance
_DEV_NAME_B64 = "REVWRUxPUEVSIC0gTkFKTUkgRkYgRVhQRVJJTUVOVA=="  # DEVELOPER - BATMANXD
_DEV_TG_B64 = "VEcgVVNFUk5BTUU6IEBOQUpNSV9BRE1JTg=="            # TG USERNAME: @BATMANXD

DEVELOPER_INFO = {
    "developer": base64.b64decode(_DEV_NAME_B64).decode('utf-8'),
    "telegram": base64.b64decode(_DEV_TG_B64).decode('utf-8')
}

print(f"[{DEVELOPER_INFO['developer']} | {DEVELOPER_INFO['telegram']}]")

app = Flask(__name__)

jwt_tokens = {}
jwt_expiry = {}
jwt_lock = threading.Lock()

def proto_to_dict(message):
    """
    Safely converts protobuf to dict without relying on buggy 'label' attributes.
    """
    result = {}
    
    for field in getattr(message.DESCRIPTOR, 'fields', []):
        value = getattr(message, field.name)
        val_type = type(value).__name__
        
        if 'MapContainer' in val_type:
            map_result = {}
            for k, v in value.items():
                if hasattr(v, 'DESCRIPTOR'):
                    map_result[k] = proto_to_dict(v)
                elif isinstance(v, bytes):
                    map_result[k] = binascii.hexlify(v).decode('utf-8')
                else:
                    map_result[k] = v
            result[field.name] = map_result
            
        elif 'Repeated' in val_type:
            list_result = []
            for item in value:
                if hasattr(item, 'DESCRIPTOR'):
                    list_result.append(proto_to_dict(item))
                elif isinstance(item, bytes):
                    list_result.append(binascii.hexlify(item).decode('utf-8'))
                else:
                    list_result.append(item)
            result[field.name] = list_result
            
        elif hasattr(value, 'DESCRIPTOR'):
            result[field.name] = proto_to_dict(value)
            
        elif getattr(field, 'type', None) == 14: # 14 is FieldDescriptor.TYPE_ENUM
            try:
                result[field.name] = field.enum_type.values_by_number[value].name
            except:
                result[field.name] = value
                
        elif isinstance(value, bytes):
            result[field.name] = binascii.hexlify(value).decode('utf-8') if value else ""
            
        else:
            result[field.name] = value

    return result


def extract_token_from_response(data, region):
    """Safely extract JWT token from API response."""
    if not isinstance(data, dict):
        return None
    
    if "jwt_token" in data:
        return data["jwt_token"]
    if "token" in data:
        return data["token"]
        
    if data.get("success") is True and "token" in data:
        return data["token"]
    
    if region == "IND":
        if data.get('status') in ['success', 'live']:
            return data.get('token')
    elif region in ["BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH"]:
        if 'token' in data:
            return data['token']
    else:
        if data.get('status') == 'success':
            return data.get('token')
    
    return None

def ensure_jwt_token_sync(region):
    """Ensure JWT token is available; fetch/refresh automatically using the new JWT API."""
    global jwt_tokens, jwt_expiry
    current_time = time.time()

    if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
        return jwt_tokens[region]

    with jwt_lock:
        if region in jwt_tokens and current_time < jwt_expiry.get(region, 0):
            return jwt_tokens[region]

        print(f"[JWT] Token missing or expired for region {region}. Fetching...")

        # Updated API endpoint provided
        url = "https://najmi-jwt-toekn-gen.vercel.app/api/get_jwt?guest_uid=4536993411&guest_password=EFDDEC1D960EF0C3E3153037E0A19BA06C5515067DCC2D405EBCB4C5400E27D9"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            token = extract_token_from_response(data, region)

            if token:
                jwt_tokens[region] = token
                jwt_expiry[region] = current_time + 300
                print(f"[JWT] Token updated successfully: {token[:50]}...")
                return token
            else:
                print(f"[JWT] Failed to extract token from response: {data}")

        except Exception as e:
            print(f"[JWT] Request error: {e}")

    return jwt_tokens.get(region)


def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
        "ID": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "VN": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TH": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "default": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])

default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, region):
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        data = bytes.fromhex(idd)
        response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"[API] Request to {endpoint} failed: {e}")
        raise


@app.route('/', methods=['GET'])
def home():
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FF Player Info</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {{
                --primary: #FF4655;
                --accent: #00FF94;
                --bg-dark: #0f172a;
                --glass: rgba(255, 255, 255, 0.05);
                --glass-border: rgba(255, 255, 255, 0.1);
            }}

            * {{ margin: 0; padding: 0; box-sizing: border-box; }}

            body {{
                font-family: 'Outfit', sans-serif;
                background-color: var(--bg-dark);
                background-image: 
                    radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%), 
                    radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%), 
                    radial-gradient(at 100% 0%, hsla(339,49%,30%,1) 0, transparent 50%);
                color: white;
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                overflow: hidden;
            }}

            .bg-animation {{
                position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
                background-size: 40px 40px;
                background-image:
                  linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                  linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            }}

            .container {{
                position: relative; background: var(--glass);
                backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
                border: 1px solid var(--glass-border); padding: 3rem 2rem;
                border-radius: 24px; text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                max-width: 600px; width: 90%; animation: float 6s ease-in-out infinite;
            }}

            h1 {{
                font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem;
                background: linear-gradient(to right, #fff, #cbd5e1);
                -webkit-background-clip: text; -webkit-text-fill-color: transparent;
                letter-spacing: -1px; text-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
            }}

            .badge {{
                display: inline-flex; align-items: center; gap: 8px;
                background: rgba(0, 255, 148, 0.1); border: 1px solid rgba(0, 255, 148, 0.2);
                color: var(--accent); padding: 8px 16px; border-radius: 100px;
                font-size: 0.9rem; font-weight: 500; font-family: 'JetBrains Mono', monospace;
                margin-bottom: 2rem; box-shadow: 0 0 15px rgba(0, 255, 148, 0.1);
            }}

            .dot {{
                width: 8px; height: 8px; background-color: var(--accent);
                border-radius: 50%; animation: pulse 2s infinite;
            }}

            .code-box {{
                background: rgba(0, 0, 0, 0.3); border: 1px solid var(--glass-border);
                border-radius: 12px; padding: 1.5rem; margin: 0 auto 1rem auto;
                font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;
                color: #a5b4fc; word-break: break-all; cursor: pointer; transition: all 0.3s ease;
            }}
            
            .code-box:last-of-type {{ margin-bottom: 2.5rem; }}
            .code-box:hover {{ border-color: rgba(255, 255, 255, 0.3); transform: translateY(-2px); }}

            .footer-links {{ display: flex; flex-direction: column; gap: 12px; margin-top: 1rem; }}

            .btn {{
                text-decoration: none; padding: 12px 20px; border-radius: 12px;
                font-weight: 500; transition: all 0.3s ease; display: flex;
                align-items: center; justify-content: center; gap: 10px;
            }}

            .btn-credit {{ background: rgba(255, 255, 255, 0.03); border: 1px solid var(--glass-border); color: #e2e8f0; }}
            .btn-credit:hover {{ background: rgba(255, 255, 255, 0.1); border-color: #e2e8f0; }}

            .btn-power {{
                background: linear-gradient(45deg, #4f46e5, #06b6d4); color: white;
                box-shadow: 0 10px 20px -10px rgba(79, 70, 229, 0.5);
            }}
            .btn-power:hover {{ filter: brightness(1.1); transform: scale(1.02); box-shadow: 0 15px 30px -10px rgba(79, 70, 229, 0.6); }}

            @keyframes pulse {{
                0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 148, 0.7); }}
                70% {{ transform: scale(1); box-shadow: 0 0 0 10px rgba(0, 255, 148, 0); }}
                100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 148, 0); }}
            }}

            @keyframes float {{
                0% {{ transform: translateY(0px); }}
                50% {{ transform: translateY(-10px); }}
                100% {{ transform: translateY(0px); }}
            }}
        </style>
    </head>
    <body>
        <div class="bg-animation"></div>
        <div class="container">
            <h1>Free Fire<br>Player Info API</h1>
            <div class="badge"><div class="dot"></div>API IS RUNNING</div>
            <div class="code-box" onclick="copyText('/info?uid={{uid}}')">/info?uid={{uid}}</div>
            <div class="code-box" onclick="copyText('/wishlist?uid={{uid}}')">/wishlist?uid={{uid}}</div>
            <div class="footer-links">
                <a href="https://t.me/NAJMI_ADMIN" target="_blank" class="btn btn-credit">
                    <i class="fab fa-telegram"></i><span>Dev: {DEVELOPER_INFO['developer']}</span>
                </a>
                <a href="https://t.me/NAJMI_ADMIN" target="_blank" class="btn btn-power">
                    <i class="fas fa-bolt"></i><span>Telegram: @NAJMI_ADMIN</span>
                </a>
            </div>
        </div>
        <script>function copyText(text) {{ navigator.clipboard.writeText(text); }}</script>
    </body>
    </html>
    """
    return html_content


@app.route('/info', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        api_response = apis(encrypted_hex, region)
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        
        result = proto_to_dict(message)
        return jsonify(result)
    
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"[ERROR] Processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

@app.route('/wishlist', methods=['GET'])
def get_wishlist_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'default').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = int(uid)
        
        protobuf_data = req.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        base_endpoint = get_api_endpoint(region)
        wishlist_url = base_endpoint.replace("GetPlayerPersonalShow", "GetWishListItems")
        
        token = ensure_jwt_token_sync(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = requests.post(wishlist_url, headers=headers, data=bytes.fromhex(encrypted_hex), timeout=10)
        response.raise_for_status()
        resp_hex = response.content.hex()
        
        res = GetWishListItems_pb2.CSGetWishListItemsRes()
        res.ParseFromString(bytes.fromhex(resp_hex))
        
        result = proto_to_dict(res)
        
        return jsonify(result)

    except Exception as e:
        print(f"[ERROR] Wishlist request: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 404

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)