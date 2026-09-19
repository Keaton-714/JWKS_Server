from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid
import time
import jwt
import json

app = Flask(__name__)

# RSA key generation
def generateKey(expiry):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = str(uuid.uuid4()) # unique ID
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key)) # Convert JSON string into python dictionary

    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"

    return {
        "kid": kid, 
        "expiry": expiry,
        "public_key": public_key,
        "private_key": private_key,
        "jwk": jwk
    }

valid_key = generateKey(time.time() + 3600)
expired_key = generateKey(time.time() - 3600)
keys = [valid_key, expired_key]


# Auth enpoint
@app.route("/auth", methods = ["POST"])
def auth():

    if ("expired" in request.args):
        selected_key = expired_key
    else:
        selected_key = valid_key

    payload = {
        "sub": "defaultUser",
        "exp": int(selected_key["expiry"])
    }

    # Create and sign jwt
    token = jwt.encode(
    payload,
    selected_key["private_key"],
    algorithm="RS256",
    headers={"kid": selected_key["kid"]}
    )

    return token

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    valid_jwks = []

    for key in keys:
        if (key["expiry"] > time.time()):
            valid_jwks.append(key["jwk"])

    return { "keys": valid_jwks }

if (__name__ == "__main__"):
    app.run(port=8080)
