from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import rsa
import time
import jwt
import json
import sqlite3
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect("totally_not_my_privateKeys.db")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def save_key(private_key_pem, expiry):
    conn = sqlite3.connect("totally_not_my_privateKeys.db")

    cursor = conn.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (private_key_pem, int(expiry))
    )

    conn.commit()
    kid = cursor.lastrowid
    conn.close()

    return kid

def get_key(expired=False):
    conn = sqlite3.connect("totally_not_my_privateKeys.db")

    if expired:
        cursor = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
            (int(time.time()),)
        )
    else:
        cursor = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
            (int(time.time()),)
        )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None
    
    kid, private_key_pem, expiry = row

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    return {
        "kid": str(kid),
        "private_key": private_key,
        "expiry": expiry
    }

def get_valid_keys():
    conn = sqlite3.connect("totally_not_my_privateKeys.db")

    cursor = conn.execute(
        "SELECT kid, key FROM keys WHERE exp > ?",
        (int(time.time()),)
    )

    rows = cursor.fetchall()
    conn.close()

    return rows

# RSA key generation
def generateKey(expiry):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    kid = save_key(private_key_pem, expiry) # unique ID
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key)) # Convert JSON string into python dictionary

    jwk["kid"] = str(kid)
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"

    return {
        "kid": str(kid), 
        "expiry": expiry,
        "public_key": public_key,
        "private_key": private_key,
        "jwk": jwk
    }

init_db()
generateKey(time.time() + 3600)
generateKey(time.time() - 3600)

# Auth enpoint
@app.route("/auth", methods = ["POST"])
def auth():

    selected_key = get_key(expired="expired" in request.args)

    if selected_key is None:
        return {"error": "No matching key found"}, 500

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

    rows = get_valid_keys()

    for kid, private_key_pem in rows:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        public_key = private_key.public_key()

        jwk = json.loads(
            jwt.algorithms.RSAAlgorithm.to_jwk(public_key)
        )

        jwk["kid"] = str(kid)
        jwk["use"] = "sig"
        jwk["alg"] = "RS256"

        valid_jwks.append(jwk)

    return {"keys": valid_jwks}

if (__name__ == "__main__"):
    app.run(port=8080)
