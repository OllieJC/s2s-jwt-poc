from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import json
import os
import time
import jwt
import requests

class AuthError(Exception):
    pass

app = Flask(__name__)

def fetch_client_md(md_url: str) -> dict:
    r = requests.get(md_url, timeout=3)
    if r.status_code != 200:
        raise AuthError(f"metadata fetch failed {r.status_code}")
    return r.json()

def verify_jwt():
    """
    Returns (client_id, jti) if verification passes.
    - authorization: "Bearer <jwt>"
    """
    authorization = request.headers.get("Authorization", None)
    # get full request URL
    aud = request.url

    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("missing bearer token")
    token = authorization.split(" ", 1)[1]

    # get JWT header from token
    jwt_header = jwt.get_unverified_header(token)
    jwt_payload = jwt.decode(token, options={"verify_signature": False})

    iss = jwt_payload.get("iss")

    md = fetch_client_md(iss)
    client_id = md.get("client_id", None)
    if not client_id:
        raise AuthError("client_id not found")
    if client_id != iss:
        raise AuthError("client_id mismatch")

    jwks_uri = md.get("jwks_uri", None)
    if not jwks_uri:
        raise AuthError("jwks_uri not found")

    jwk_client = jwt.PyJWKClient(jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["ES256"],
        audience=aud,
        options={"require": ["iss","aud","exp","iat","jti"]}
    )
    if claims["exp"] < int(time.time()):
        raise AuthError("token expired")
    return client_id, claims["jti"]

counter = {

}

@app.route("/api/get-counter", methods=["GET"])
def route_get_counter():
    global counter
    client_id, jti = verify_jwt()
    return jsonify({"counter": len(counter.get(client_id, []))})

@app.route("/api/increment-counter", methods=["POST"])
def route_inc_counter():
    global counter
    success = False
    client_id, jti = verify_jwt()
    if client_id not in counter:
        counter[client_id] = []
    if jti not in counter[client_id]:
        counter[client_id].append(jti)
        success = True
    return jsonify({"success": success})

if __name__ == "__main__":
    app.run(debug=True, port=5006)
