from flask import Flask, request, jsonify
import base64, json, os, hmac, hashlib
from threading import Lock

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Data classes (Python dicts instead of Go structs) ---
class Student:
    def __init__(self, id, name, gpa):
        self.id = id
        self.name = name
        self.gpa = gpa

    def to_dict(self):
        return {"id": self.id, "name": self.name, "gpa": self.gpa}

# --- Globals ---
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
session_keys = {}
sess_lock = Lock()

app = Flask(__name__)

# --- Helpers ---
def new_session_id():
    return os.urandom(16).hex()

def compute_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def decrypt_aes(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- Routes ---
@app.route("/publicKey", methods=["GET"])
def handle_public_key():
    try:
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        resp = {"publicKey": base64.b64encode(der).decode("utf-8")}
        return jsonify(resp)
    except Exception as e:
        return ("failed to marshal public key", 500)

@app.route("/session", methods=["POST"])
def handle_session():
    try:
        req = request.get_json()
        enc_key_bytes = base64.b64decode(req["encryptedKey"])
        symm_key = private_key.decrypt(
            enc_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        session_id = new_session_id()
        with sess_lock:
            session_keys[session_id] = symm_key
        print(f"New session created: {session_id} (key length={len(symm_key)})")
        return jsonify({"sessionID": session_id})
    except Exception as e:
        return (f"failed to decrypt symmetric key: {e}", 400)

@app.route("/message", methods=["POST"])
def handle_message():
    try:
        req = request.get_json()
        session_id = req["sessionID"]
        with sess_lock:
            key = session_keys.get(session_id)
        if key is None:
            return ("unknown session ID", 400)

        ciphertext = base64.b64decode(req["ciphertext"])
        nonce = base64.b64decode(req["nonce"])
        recv_hmac = base64.b64decode(req["hmac"])

        expected_hmac = compute_hmac(key, ciphertext)
        if not hmac.compare_digest(expected_hmac, recv_hmac):
            return jsonify({
                "validHMAC": False,
                "message": "HMAC verification failed (message may be tampered)."
            })

        try:
            plaintext = decrypt_aes(key, nonce, ciphertext)
        except Exception as e:
            return jsonify({
                "validHMAC": True,
                "message": f"HMAC ok but decryption failed: {e}"
            })

        try:
            stu_data = json.loads(plaintext.decode("utf-8"))
            stu = Student(stu_data["id"], stu_data["name"], stu_data["gpa"])
        except Exception as e:
            return jsonify({
                "validHMAC": True,
                "message": f"HMAC ok; failed to unmarshal student JSON: {e}"
            })

        print(f"Received valid message for session {session_id}: {stu_data}")
        return jsonify({
            "validHMAC": True,
            "message": "HMAC verified and message decrypted successfully",
            "student": stu.to_dict()
        })
    except Exception as e:
        return (f"invalid request: {e}", 400)

# --- Main ---
if __name__ == "__main__":
    print("RSA key pair generated")
    app.run(host="0.0.0.0", port=8080)