from flask import Flask, jsonify, request, render_template
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import json
import os
import time
import jwt
import uuid
import base64
import requests

app = Flask(__name__)

BACKEND_HOST = os.getenv("BACKEND_HOST", "http://localhost:5006")

BACKEND_ENDPOINT_GET = f"{BACKEND_HOST}/api/get-counter?v=1"
BACKEND_ENDPOINT_INCREMENT = f"{BACKEND_HOST}/api/increment-counter?v=1"

EC_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEQCq8uM6YMxHg2OMJp3egDYxF2P
aj5w/EoAuEtiBAo1yHhUdV8tXElAj69Wzn3dPOadeVyrTXXwCDNn68Dqag==
-----END PUBLIC KEY-----"""

EC_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgL+qTsxRmpD/l+Wck
m7Dc2HkPwL4aJwDSkVkVb8TJ3YyhRANCAAR8RAKry4zpgzEeDY4wmnd6ANjEXY9q
PnD8SgC4S2IECjXIeFR1Xy1cSUCPr1bOfd085p15XKtNdfAIM2frwOpq
-----END PRIVATE KEY-----"""


def get_client_id():
    host = request.host_url.rstrip('/')
    return f"{host}/.well-known/client.json"

def get_jwt(aud):
    client_id = get_client_id()

    jwt_header = {
        "alg": "ES256",
        "kid": "abc123"
    }

    _iat = int(time.time())

    jwt_payload = {
        "iss": client_id,
        "aud": aud,
        "exp": _iat + 60,
        "iat": _iat,
        "jti": str(uuid.uuid4())
    }
    signed_jwt = jwt.encode(jwt_payload, EC_PRIVATE_KEY, algorithm="ES256", headers=jwt_header)

    return signed_jwt, jwt_header, jwt_payload

def do_counter_get():
    signed_jwt, jwt_header, jwt_payload = get_jwt(aud=BACKEND_ENDPOINT_GET)

    # fetch from backend using requests
    try:
        response = requests.get(BACKEND_ENDPOINT_GET, headers={"Authorization": f"Bearer {signed_jwt}"})
        if response.status_code == 200:
            return response.json().get("counter", 0), signed_jwt, jwt_header, jwt_payload
    except Exception as e:
        print(f"Error fetching counter: {e}")
        return -1, signed_jwt, jwt_header, jwt_payload
    return -1, signed_jwt, jwt_header, jwt_payload

def do_counter_increment():
    signed_jwt, jwt_header, jwt_payload = get_jwt(aud=BACKEND_ENDPOINT_INCREMENT)

    # fetch from backend using requests
    try:
        response = requests.post(BACKEND_ENDPOINT_INCREMENT, headers={"Authorization": f"Bearer {signed_jwt}"})
        if response.status_code == 200:
            return response.json().get("success", False), signed_jwt, jwt_header, jwt_payload
    except Exception as e:
        print(f"Error incrementing counter: {e}")
        return False, signed_jwt, jwt_header, jwt_payload
    return False, signed_jwt, jwt_header, jwt_payload


@app.get("/")
def index():
    counter, get_jwt, get_jwt_header, get_jwt_payload = do_counter_get()
    if counter == -1:
        counter = "(error fetching)"

    increment_success, increment_jwt, increment_jwt_header, increment_jwt_payload = do_counter_increment()
    increment_status = "Yes" if increment_success else "No"

    # pretty print HTML for jwt components
    get_jwt_header = json.dumps(get_jwt_header, indent=4).replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")
    get_jwt_payload = json.dumps(get_jwt_payload, indent=4).replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")
    increment_jwt_header = json.dumps(increment_jwt_header, indent=4).replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")
    increment_jwt_payload = json.dumps(increment_jwt_payload, indent=4).replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")

    return render_template("index.html",
        client_id=get_client_id(),
        jwks_uri=get_client_id().replace("client.json", "jwks.json"),
        counter=counter,
        backend_endpoint_get=BACKEND_ENDPOINT_GET,
        get_jwt=get_jwt,
        get_jwt_header=get_jwt_header,
        get_jwt_payload=get_jwt_payload,
        backend_endpoint_increment=BACKEND_ENDPOINT_INCREMENT,
        increment_jwt=increment_jwt,
        increment_jwt_header=increment_jwt_header,
        increment_jwt_payload=increment_jwt_payload,
        increment_status=increment_status
    )

@app.route('/.well-known/client.json')
def client_md():
    # hostname from request
    host = request.host_url.rstrip('/')
    return jsonify({
        "client_id": get_client_id(),
        "jwks_uri": f"{host}/.well-known/jwks.json"
    })

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def ec_pub_pem_to_jwk(pem_bytes: bytes, kid: str) -> dict:
    """Convert EC public key (PEM) to JWK dict."""
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected EC public key")

    nums = key.public_numbers()
    curve_name = key.curve.name
    # Map OpenSSL names to JWK 'crv' names
    curve_map = {
        "secp256r1": "P-256",
        "prime256v1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521"
    }
    crv = curve_map.get(curve_name, curve_name)

    x = _b64u(nums.x.to_bytes((nums.x.bit_length() + 7) // 8, "big"))
    y = _b64u(nums.y.to_bytes((nums.y.bit_length() + 7) // 8, "big"))

    return {
        "kty": "EC",
        "use": "sig",
        "crv": crv,
        "x": x,
        "y": y,
        "alg": f"ES{crv.split('-')[1]}",
        "kid": kid
    }

@app.route('/.well-known/jwks.json')
def jwks():
    _kid = "abc123"  # Example key ID
    return jsonify({
        "keys": [
            ec_pub_pem_to_jwk(EC_PUBLIC_KEY.encode(), _kid)
        ]
    })

if __name__ == '__main__':
    app.run(debug=True)
