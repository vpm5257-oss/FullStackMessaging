import hmac
import hashlib
import base64
import json
import sys
import os
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Full Stack Messaging
class Student:
    def __init__(self,ID,name,GPA):
        self.ID = ID
        self.name = name
        self.GPA = GPA

    def to_dict(self):
        return {
        "ID": self.ID,
        "name": self.name,
        "GPA": self.GPA
        }

    @classmethod
    def from_dict(cls, data):
        return cls(data["ID"],data["name"],data["GPA"])
    
#Step 1 Serialization

Student1 = Student(1,"Alexa",3.5)

Student_json = json.dumps(Student1.to_dict())
print("Customer 1 object serialized to JSON string:")
print(Student_json)

#Step 2 Connectivity and #Step 4 Key Exchange 
#Client calls an API to gets the public key from a Server Web Service
server_base = "http://localhost:8080"
def fetch_server_public_key(server_base):
    # Placeholder for actual implementation
    # Should return the public key or raise an exception if it fails
    return "mock_public_key"

try:
    pub_key = fetch_server_public_key(server_base)
    print("Step 4: Received server public key")
except Exception as e:
    # Equivalent to log.Fatalf in Go (terminates program with error)
    print(f"failed to get public key: {e}", file=sys.stderr)
    sys.exit(1)


#Step 3 and 5: Key Generation and Key Exchnage
#Key Exchange: Client uses the public key to encrypt the symmetric key which is sent to the server and the server uses the
#private key to decrypt it

def send_symmetric_key(server_base, pub_key, symm_key):
    # Placeholder for actual implementation
    # Should return a session ID or raise an exception if it fails
    return "mock_session_id"

try:
    # Generate 32 random bytes for AES-256
    symm_key = os.urandom(32)
    print("Step 3: Generated symmetric key")
except Exception as e:
    print(f"failed to generate symmetric key: {e}", file=sys.stderr)
    sys.exit(1)

try:
    session_id = send_symmetric_key(server_base, pub_key, symm_key)
except Exception as e:
    print(f"failed to send symmetric key: {e}", file=sys.stderr)
    sys.exit(1)

print("Step 5: Encrypted symmetric key sent to server, sessionID =", session_id)


#Step 6 Encryption
def encryptAES(symmKey: bytes, studentJSON: bytes):
    try:
        # Generate a random nonce (12 bytes is standard for AES-GCM)
        nonce = os.urandom(12)
        aesgcm = AESGCM(symmKey)
        ciphertext = aesgcm.encrypt(nonce, studentJSON, None)
        return nonce, ciphertext, None
    except Exception as e:
        return None, None, e

symmKey = AESGCM.generate_key(bit_length=128)  # 16-byte key
studentJSON = b'student_json ={"ID":1,"name":"Alexa","GPA":3.5}'

nonce, ciphertext, err = encryptAES(symmKey, studentJSON)
if err:
    sys.exit(f"AES encryption failed: {err}")

print("Step 6: Encrypted student JSON with AES")

#Step 7 Integrity Client generates the SHA256 using HMAC on the message using the session symmetric key

def compute_hmac(message, secret_key):
    hash_algorithm = hashlib.sha256 #hash Function
    hmac_object = hmac.new(secret_key.encode(), message.encode(), hash_algorithm) #Computing HMAC
    hmac_digest = hmac_object.digest()                                            #HMAC Value
    encoded_hmac = base64.b64encode(hmac_digest).decode()  # Base64 encoding
    return encoded_hmac

#Step 8 Server receives the HMAC and message and generates the HMAC perform equality check using the session
#symmetric key and #Step 9 Decryption
# --- Fetch server public key ---
def fetch_server_public_key(base: str):
    try:
        resp = requests.get(base + "/publicKey")
        resp.raise_for_status()
        pk_resp = resp.json()

        der = base64.b64decode(pk_resp["PublicKey"])
        pub_key = serialization.load_der_public_key(der)

        # Ensure it's RSA
        from cryptography.hazmat.primitives.asymmetric import rsa
        if not isinstance(pub_key, rsa.RSAPublicKey):
            raise ValueError("Parsed key is not RSA public key")

        return pub_key
    except Exception as e:
        raise RuntimeError(f"Failed to fetch public key: {e}")


# --- Send symmetric key encrypted with RSA ---
def send_symmetric_key(base: str, pub_key, key: bytes):
    try:
        enc_key = pub_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        req_body = {"EncryptedKey": base64.b64encode(enc_key).decode("utf-8")}
        resp = requests.post(base + "/session", json=req_body)
        if resp.status_code != 200:
            raise RuntimeError(f"Server returned {resp.status_code}: {resp.text}")

        sess_resp = resp.json()
        return sess_resp["SessionID"]
    except Exception as e:
        raise RuntimeError(f"Failed to send symmetric key: {e}")


# --- Encrypt with AES-GCM ---
def encrypt_aes(key: bytes, plaintext: bytes):
    try:
        nonce = os.urandom(12)  # AES-GCM standard nonce size
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext
    except Exception as e:
        raise RuntimeError(f"AES encryption failed: {e}")


# --- Send encrypted message ---
def send_encrypted_message(base: str, session_id: str, nonce: bytes, ciphertext: bytes, mac: bytes):
    try:
        req = {
            "SessionID": session_id,
            "Ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "Nonce": base64.b64encode(nonce).decode("utf-8"),
            "HMAC": base64.b64encode(mac).decode("utf-8"),
        }

        resp = requests.post(base + "/message", json=req)
        resp.raise_for_status()
        msg_resp = resp.json()

        print("Server response:")
        print(f"  ValidHMAC: {msg_resp.get('ValidHMAC')}")
        print(f"  Message  : {msg_resp.get('Message')}")
        if msg_resp.get("Student") is not None:
            print(f"  Student  : {msg_resp['Student']}")

    except Exception as e:
        raise RuntimeError(f"Sending encrypted message failed: {e}")


if __name__ == "__main__":
    server_base = "http://localhost:8080"  # replace with actual server
    student_json = b'{"ID":1,"name":"Alexa","GPA":3.5}'

    # Fetch public key
    pub_key = fetch_server_public_key(server_base)

    # Generate symmetric AES key
    symm_key = AESGCM.generate_key(bit_length=128)

    # Send symmetric key to server
    session_id = send_symmetric_key(server_base, pub_key, symm_key)

    # Encrypt student JSON
    nonce, ciphertext = encrypt_aes(symm_key, student_json)

    # Compute HMAC (example: SHA256)
    import hmac, hashlib
    mac = hmac.new(symm_key, ciphertext, hashlib.sha256).digest()

    # Send encrypted message
    send_encrypted_message(server_base, session_id, nonce, ciphertext, mac)

#Step 10  Deserialization
Student_data = json.loads(Student_json)
Student2 = Student.from_dict(Student_data)
print("Deserialized back into Student object:")
print(f"ID: {Student2.ID}, Name: {Student2.name}, GPA: {Student2.GPA}")