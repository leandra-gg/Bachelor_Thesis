import base64
import hashlib
import logging 
import sqlite3
import json
import requests
import os
import time
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from web3 import Web3
from web3.exceptions import TransactionNotFound
from google.cloud import storage
import secrets
import jwt
from jwt import PyJWKClient

#config
WEB3_PROVIDER= "https://sepolia.optimism.io"
PRIVATE_KEY= "590e4ce1dc09acd32160a8c1cdb22f9c12d3b66220b4a3b147be1bf0cb81a087"
REGISTRY_CONTRACT_ADDRESS= "0x5c36D354F9d4446cB67eE5Ec0ef7B120240318e2"
AUDIT_TRAIL_CONTRACT_ADDRESS= "0x880809b98bD311F83237A741Bb01288abC47ae4f"

DB_PATH="/app/orchestrator.db"
ORCHESTRATOR_URL=os.getenv("ORCHESTRATOR_URL","")
SELF_CERT="orchestrator.crt"
MACHINE_ID= "orchestrator011551155"
BUCKET_NAME=os.getenv("BUCKET_NAME","orchestrator00-bucket")
ORCHESTRATOR_ISSUER = "https://confidentialcomputing.googleapis.com"

conf = requests.get("https://confidentialcomputing.googleapis.com/.well-known/openid-configuration").json()
jwks_uri = conf["jwks_uri"]
jwks_client = PyJWKClient(conf["jwks_uri"])

timestamp = datetime.now(timezone.utc).isoformat().replace(":", "_")
LOG_PATH = os.path.join(f"{MACHINE_ID}_{timestamp}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
MAX_RETRIES=3
SKIP_ATTESTATION = os.getenv("SKIP_ATTESTATION", "true").lower() == "true"
SKIP_CHAIN = os.getenv("SKIP_CHAIN", "true").lower() == "true"
PROJECT_ID = os.getenv("PROJECT_ID", "orchestrator011551155")
REGION = os.getenv("REGION", "europe-west1")
PARENT = f"projects/{PROJECT_ID}/locations/{REGION}"

MACHINE1_URL=os.getenv("MACHINE1_URL","https://MACHINE1_IP:5000/prepare")
MACHINE2_URL=os.getenv("MACHINE2_URL","https://MACHINE2_IP:5000/anonymize")
MACHINE3_URL=os.getenv("MACHINE3_URL","https://MACHINE3_IP:5000/analyse")
MACHINE4_URL=os.getenv("MACHINE4_URL","https://MACHINE4_IP:5000/decision")

EXPECTED_DIGESTS = {
    "1": os.getenv("IMAGE_DIGEST_1"),
    "2": os.getenv("IMAGE_DIGEST_2"),
    "3": os.getenv("IMAGE_DIGEST_3"),
    "4": os.getenv("IMAGE_DIGEST_4")
}

#initiliaze services
app = Flask(__name__)
w3=Web3(Web3.HTTPProvider(WEB3_PROVIDER))
ACCOUNT_ADDRESS = w3.eth.account.from_key(PRIVATE_KEY).address
storage_client=storage.Client()

#contracts
with open("build/PublicKeyRegistry.json") as f:
    registry_abi=json.load(f)["abi"]

with open("build/AuditTrail.json") as f:
    audit_abi=json.load(f)["abi"]

public_key_registry=w3.eth.contract(
    address=Web3.to_checksum_address(REGISTRY_CONTRACT_ADDRESS),abi=registry_abi)

audit_trail=w3.eth.contract(
    address=Web3.to_checksum_address(AUDIT_TRAIL_CONTRACT_ADDRESS), abi=audit_abi)

#sqlite db setup
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registration_nonce (
                machine_address TEXT PRIMARY KEY,
                nonce TEXT,
                timestamp TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_nonce (
                machine_address TEXT PRIMARY KEY,
                nonce TEXT,
                timestamp TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registered_machines(
                machine_address TEXT PRIMARY KEY,
                cert_pem_base64 TEXT,
                expected_build_hash TEXT
            )
        """)
        conn.commit()
        logging.info("init db tables created successfully")

# only if not existing
if not os.path.exists(DB_PATH):
    logging.warning(f"{DB_PATH} not found. Will be created on first run.")
else:
    logging.info(f"{DB_PATH} already exists. Tables will only be created if missing.")

init_db()


def load_registration_nonce(machine_address):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT nonce, timestamp FROM registration_nonce WHERE machine_address=?", (machine_address,))
        return cursor.fetchone()

def save_registration_nonce(machine_address, nonce):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT or REPLACE INTO registration_nonce (machine_address, nonce, timestamp) VALUES (?, ?, ?)",
            (machine_address, nonce, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        
def load_audit_nonce(machine_address):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT nonce, timestamp FROM audit_nonce WHERE machine_address=?", (machine_address,))
        return cursor.fetchone()

def save_audit_nonce(machine_address, nonce):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT or REPLACE INTO audit_nonce (machine_address, nonce, timestamp) VALUES (?, ?, ?)",
            (machine_address, nonce, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
    
def load_machine_certificate(machine_address):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT cert_pem_base64 FROM registered_machines WHERE machine_address=?", (machine_address,))
        row = cursor.fetchone()
        return base64.b64decode(row[0]) if row else None

    
def load_expected_build_hash(machine_address):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT expected_build_hash FROM registered_machines WHERE machine_address=?", (machine_address,))
        row = cursor.fetchone()
        return row[0] if row else None


def save_machine_metadata(machine_address, cert_pem_b64, expected_build_hash=None):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        logging.debug(f"Saving machine {machine_address}: build_hash={expected_build_hash}")

        cursor.execute(
            "INSERT OR REPLACE INTO registered_machines(machine_address, cert_pem_base64, expected_build_hash) VALUES (?, ?, ?)",
            (machine_address, cert_pem_b64, expected_build_hash)
        )
        conn.commit()

@app.route("/get_registration_nonce", methods=["POST"])
def get_registration_nonce():
    data=request.get_json()
    machine_address=data["machine_address"]
    try:
        nonce = secrets.token_hex(16)
        save_registration_nonce(machine_address, nonce)
        return jsonify({
            "nonce": nonce,
        }), 200
    except Exception as e:
        logging.error(f"Error creating registration nonce:{e}", exc_info=True)
        return jsonify({"error": "Failed to create registration nonce"}), 500
    
@app.route("/get_audit_nonce", methods=["POST"])
def get_audit_nonce():
    data=request.get_json()
    machine_address=data["machine_address"]
    try:
        nonce = secrets.token_hex(16)
        save_audit_nonce(machine_address, nonce)
        return jsonify({
            "nonce": nonce,
        }), 200
    except Exception as e:
        logging.error(f"Error creating audit nonce:{e}", exc_info=True)
        return jsonify({"error": "Failed to create audit nonce"}), 500

def compute_attestation_hash(attestation_token:str)->str:
    token_bytes=attestation_token.encode("utf-8")
    return hashlib.sha256(token_bytes).hexdigest()

def validate_attestation_token(attestation_token: str, expected_nonce: str, expected_image_digest: str):
    # 1. Fetch the signing key and decode the JWT
    body = request.get_json()
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(attestation_token).key
        decoded = jwt.decode(
            attestation_token,
            signing_key,
            algorithms=["RS256"],
            audience="orchestrator011551155",
            issuer=ORCHESTRATOR_ISSUER
        )
    except Exception as e:
        raise ValueError(f"Token decoding failed or signature invalid: {e}")
    #verify nonce
    if expected_nonce not in decoded.get("eat_nonce", []):
        raise ValueError("Nonce mismatch in TEE attestation token")

    #verify the image digest matches the one we expect
    container_info = decoded.get("submods", {}).get("container", {})
    token_digest   = container_info.get("image_digest")
    if token_digest.startswith("sha256:"):
        token_digest = token_digest.split(":", 1)[1]
    if expected_image_digest.startswith("sha256:"):
        expected_image_digest=expected_image_digest.split(":", 1)[1]
    if token_digest != expected_image_digest:
        raise ValueError(
        f"Image digest mismatch: token has '{token_digest}', expected '{expected_image_digest}'"
        )

    # 4. Verify TEE claims (hardware model & secure boot)
    if decoded.get("hwmodel") != "GCP_AMD_SEV" or not decoded.get("secboot", False):
        raise ValueError("Invalid TEE environment in attestation token")

    return decoded
    
    
@app.route("/is_machine_registered", methods=["POST"])
def is_machine_registered():
    try:
        data = request.get_json()
        logging.info(f"Checking is machine registered: {json.dumps(data, indent=2)}")
        machine_address = data["machine_address"]
        is_active = public_key_registry.functions.isMachineActive(machine_address).call()
        return jsonify({"active": is_active}), 200
    except Exception as e:
        logging.error(f"Error checking registration status: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    
@app.route("/register_machine", methods=["POST"])
def register_machine():
    try:
        data= request.get_json()
        machine_address= data.get("machine_address")
        received_nonce= data.get("nonce")
        attestation_token= data.get("attestation_token")
        public_key_hash= data.get("public_key_hash")
        cert_pem_b64= data.get("certificate_pem")
        step= int(data.get("step", -1))
        if step==-1:
            return jsonify({"error":"Missing step in registration request"}),400
        logging.info(f"Received registration request from {data.get('machine_address')}")
        logging.debug(f"Full registration payload: {json.dumps(data, indent=2)}")
        
        #attestation
        if not SKIP_ATTESTATION:
            # load the nonce originally stored
            expected_nonce, _ = load_registration_nonce(machine_address)
            # lookup the expected digest for this step
            expected_digest = EXPECTED_DIGESTS.get(str(step))
            try:
                validate_attestation_token(attestation_token, expected_nonce, expected_digest)
                logging.info(f"Attestation succeeded for {machine_address} (registration)")
            except ValueError as e:
                logging.warning(f"Registration attestation failed for {machine_address}: {e}")
                return jsonify({"error": "Attestation failed", "details": str(e)}), 400

            save_machine_metadata(machine_address, cert_pem_b64, expected_digest)
            logging.info(f"Attestation succeeded for {machine_address}")
            attestation_hash=compute_attestation_hash(attestation_token)
            logging.debug(f"Attestation hash: {attestation_hash}")
        else:
            logging.warning("SKIP_ATTESTATION=true: skipping attestation check")
            expected_digest = EXPECTED_DIGESTS.get(str(step))
            attestation_token="dummy_attestation_token"
            attestation_hash=compute_attestation_hash(attestation_token)
            save_machine_metadata(machine_address, cert_pem_b64, expected_digest)
        
        #load nonce and check timeout
        logging.debug("Loading nonce from database")
        row = load_registration_nonce(machine_address)
        if not row:
            logging.warning(f"No nonce found for machine {machine_address}")
            return jsonify({"error": "Nonce not found"}),400
        expected_nonce, timestamp_str = row
        logging.debug(f"Expected nonce: {expected_nonce}, Received nonce: {received_nonce}")
        timestamp = datetime.fromisoformat(timestamp_str)
        logging.info(f"Timestamp type: {type(timestamp)}")
        logging.info(f"Timestamp tzinfo: {timestamp.tzinfo}")
        if timestamp.tzinfo is None: 
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        current_time = datetime.now(timezone.utc)
        logging.debug(f"Nonce timestamp: {timestamp}, now: {current_time}")
        if current_time - timestamp > timedelta(minutes=5):
            return jsonify({"error": "Nonce expired"}), 400
        
        logging.debug(f"Current time: {datetime.now(timezone.utc)}")
        logging.debug(f"Timestamp: {timestamp}") 
        
        #get tls public key from cert and check hash
        logging.debug("Decoding certificate and verifying public key hash")
        try:
            cert_pem = base64.b64decode(cert_pem_b64)
            certificate = load_pem_x509_certificate(cert_pem)
        except Exception as e:
            logging.error("Failed to decode certificate PEM", exc_info=True)
            return jsonify({"error":"Invalid certificate format"}), 400
        
        public_key = certificate.public_key()
        
        recalculated_hash=hashlib.sha256(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).hexdigest()
        
        logging.debug(f"Recalculated public key hash: {recalculated_hash}")
        if recalculated_hash.lower() != public_key_hash.lower():
            return jsonify({"error": "Public Key hash mismatch"}), 400
        logging.info(f"Public key hash matched: {recalculated_hash}")
        
        #Blockchain transaction: machine registry
        logging.info(f"Registering machine on-chain: {machine_address}")
        tx_hash, receipt = send_transaction_with_retry(
            build_register_machine_tx,
            machine_address,
            public_key_hash,
            attestation_hash
        )
        logging.info(f"Registration TX confirmed in block: {receipt.blockNumber}")
        logging.info(f"Successfully registered machine {machine_address} with tx: {tx_hash.hex()}")
        return jsonify({
            "status": "registered",
            "tx_hash": tx_hash.hex()
        }), 200

    except ValueError as ve:
        logging.error(f"Registration failed: {ve}", exc_info=True)
        return jsonify({"error": "Registration failed"}), 400
    
    except Exception as e:
        logging.error(f"Error registering machine:{e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    
@app.route("/sync_metadata", methods=["POST"])
def sync_metadata():
    try:
        data = request.get_json()
        machine_address = data["machine_address"]
        cert_pem_b64 = data["certificate_pem"]
        expected_build_hash = data.get("build_hash", None)

        logging.info(f"Syncing metadata for already registered machine: {machine_address}")
        save_machine_metadata(machine_address, cert_pem_b64, expected_build_hash)

        return jsonify({"status": "metadata synced"}), 200

    except Exception as e:
        logging.error(f"Failed to sync metadata: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    
    
@app.route("/submit_audit", methods=["POST"])
def submit_audit():
    try:
        data=request.get_json()
        if not data:
            logging.error("Request JSON payload is missing or invalid!")
            return jsonify({"error": "Missing or invalid JSON payload"}), 400

        logging.info(f"Received audit submission: {json.dumps(data, indent=2)}")
        required_fields = ["machine_address", "output_hash", "signature", "gcs_url", "build_hash", "step","nonce", "attestation_token"]
        for field in required_fields:
            if not data.get(field):
                logging.error(f"Missing field: {field}")
                return jsonify({"error": f"Missing field: {field}"}), 400
        logging.info(f"Submitting audit record... {json.dumps(data, indent=2)}")
        
        machine_address=data["machine_address"]
        output_hash=data["output_hash"]
        signature=data["signature"]
        gcs_url=data["gcs_url"]
        fake_previous_hash=data.get("fake_previous_hash") #ONLY FOR TEST MODE
        received_nonce=data.get("nonce")
        attestation_token = data["attestation_token"]
        step= int(data["step"])
        cert_pem_b64 = data.get("certificate_pem")
        
        is_active=public_key_registry.functions.isMachineActive(machine_address).call()
        if not is_active:
            logging.error(f"Machine {machine_address} is not registered. Audit record submission declined.")
            return jsonify({
                "error":"Audit record submission declined",
                "details":f"Machine {machine_address} is not registered."
            }), 400
        
        #check nonce
        logging.debug(f"Checking nonce for machine {machine_address}")
        row = load_audit_nonce(machine_address)
        if not row:
            logging.warning(f"No nonce found for {machine_address}")
            return jsonify({"error": "Nonce not found"}),400
        expected_nonce, _ = row
        received_nonce = data.get("nonce")
        if received_nonce is None:
            logging.error("No nonce provided in audit submission.")
            return jsonify({"error": "Nonce missing"}), 400

        if received_nonce != expected_nonce:
            logging.error(f"Nonce mismatch: expected={expected_nonce}, received={received_nonce}")
            return jsonify({"error": "Invalid nonce"}), 400
        
        #get cert
        cert_pem_bytes = load_machine_certificate(machine_address)
        logging.debug(f"Loaded certificate for machine {machine_address}: {cert_pem_bytes[:100]}")
        if not cert_pem_bytes:
            logging.error(f"Certificate not found in DB for {machine_address}")
            return jsonify({"error": "Certificate not found"}), 400
        
        try:
            output_hash_bytes = bytes.fromhex(output_hash)
            logging.debug(f"[DEBUG] output_hash bytes: {output_hash_bytes.hex()} ({len(output_hash_bytes)} bytes)")
        except Exception as e:
            logging.error(f"[DEBUG] Failed to convert output_hash: {e}")
            return jsonify({"error": "output_hash is not valid hex"}), 400

        logging.debug(f"[DEBUG] Certificate snippet: {cert_pem_bytes[:100]}")
        
        #verify signature
        logging.debug(f"Verifying signature for machine {machine_address}")
        logging.debug(f"Calling verify_signature for hash: {output_hash}, signature: {signature[:30]}...")
        if not verify_signature(output_hash, signature, cert_pem_bytes):
            logging.error("verify_signature returned False. Signature verification failed. Audit submission rejected because of invalid signature.")
            return jsonify({"error": "Invalid signature"}), 400
        
        #attestation
        if not SKIP_ATTESTATION:
            # load the nonce we saved for audit
            expected_nonce, _ = load_audit_nonce(machine_address)
            # load the expected image digest we stored during sync_metadata
            expected_digest = load_expected_build_hash(machine_address)
            try:
                validate_attestation_token(attestation_token, expected_nonce, expected_digest)
                logging.info(f"Attestation succeeded for {machine_address} (audit)")
                attestation_hash=compute_attestation_hash(attestation_token)
                logging.debug(f"Attestation token hash: {attestation_token}")
            except ValueError as e:
                logging.warning(f"Audit attestation failed for {machine_address}: {e}")
                return jsonify({"error": "Attestation failed", "details": str(e)}), 400
        else:
            logging.warning("SKIP_ATTESTATION=true: skipping audit attestation")
            expected_digest = load_expected_build_hash(machine_address)
            attestation_token="dummy_attestation_token"
            attestation_hash=compute_attestation_hash(attestation_token)
        
        tx_hash, receipt = send_transaction_with_retry(
            build_submit_audit_tx,
            machine_address,
            output_hash,
            gcs_url,
            signature_b64=signature,
            attestation_hash=attestation_hash
        )
        logging.info(f"Audit successfully submitted by {machine_address}. TX: {tx_hash.hex()}")
        return jsonify({"status": "audit submitted", "tx_hash": tx_hash.hex()}), 200

    except Exception as e:
        logging.error(f"Error submitting audit record: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
            
@app.route('/get_latest_audit', methods=['GET'])    
def get_latest_audit():
    try:
        #check length
        length = audit_trail.functions.getAuditTrailLength().call()
        if length==0:
            return jsonify({"error": "No audit records found"}),400
        
        #get latext audit record
        latest_index=length -1
        record = audit_trail.functions.getAuditRecord(latest_index).call()
        
        machine_address= record[0]
        output_hash=Web3.to_hex(record[1])
        gcs_url=record[3]
        
        #check if machine is active/registered with registry contract
        is_active=public_key_registry.functions.isMachineActive(machine_address).call()
        if not is_active:
            return jsonify({"error": "Audit record from inactive or unregistered machine. Workflow terminated."}), 400
        
        #return answer
        return jsonify({"output_hash": output_hash, "gcs_url": gcs_url}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def verify_signature(output_hash_hex: str, signature_b64: str, cert_pem_bytes: bytes) -> bool:
    try:
        logging.debug("Starting signature verification process")
        logging.debug(f"Verifying hash: {output_hash_hex}")
        logging.debug(f"Signature (base64): {signature_b64}")
        logging.debug(f"Loaded certificate PEM:\n{cert_pem_bytes.decode()}")
        
        cert=x509.load_pem_x509_certificate(cert_pem_bytes)
        public_key=cert.public_key()
        
        output_hash_bytes=bytes.fromhex(output_hash_hex)
        if len(output_hash_bytes) != 32:
            logging.error(f"Invalid hash length: {len(output_hash_bytes)} bytes (expected 32)")
            return False
        try:
            signature = base64.b64decode(signature_b64.strip(), validate=True)
        except Exception as e:
            logging.error(f"Base64 decoding failed: {e}", exc_info=True)
            return False
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        reconstructed_hash = hashlib.sha256(public_key_bytes).hexdigest()

        logging.debug(f"[DEBUG] Hash of cert public key in verify_signature: {reconstructed_hash}")
        
        logging.debug("Using public key from certificate to verify the signature")
        public_key.verify(
            signature,
            output_hash_bytes,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256())
        )

        logging.info("Signature successfully verified")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed:{e}", exc_info=True)
        print(f"SIGNATURE VERIFICATION FAILED: {e}")
        return False
    
def send_transaction_with_retry(build_tx_func, *args, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS, 'pending')
            tx = build_tx_func(*args, nonce=nonce, **kwargs)
            signed_tx = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash, receipt
        except ValueError as ve:
            error_data = ve.args[0]
            if isinstance(error_data, dict) and error_data.get('code') == -32000:
                message = error_data.get('message', '')
                if "nonce too low" in message or "nonce too high" in message:
                    logging.warning(f"Nonce error: {message}. Retrying ({attempt+1}/{MAX_RETRIES})...")
                    time.sleep(1)
                    continue
            raise
    raise Exception("Failed to send transaction after multiple retries due to nonce issues")

def build_submit_audit_tx(machine_address, output_hash, gcs_url, signature_b64,attestation_hash, nonce):
    return audit_trail.functions.addAuditRecord(
        machine_address,
        bytes.fromhex(output_hash),
        gcs_url,
        base64.b64decode(signature_b64),
        bytes.fromhex(attestation_hash)
    ).build_transaction({
        "chainId": 11155420,
        "from": ACCOUNT_ADDRESS,
        "nonce": nonce,
        "gas": 600000,
        "type": 2,
        "maxFeePerGas": Web3.to_wei("2", "gwei"),
        "maxPriorityFeePerGas": Web3.to_wei("1", "gwei"),
    })


def build_register_machine_tx(machine_address, public_key_hash, attestation_hash, nonce):
    return public_key_registry.functions.registerMachine(
        machine_address,
        bytes.fromhex(public_key_hash),
        bytes.fromhex(attestation_hash)
    ).build_transaction({
        "chainId": 11155420,
        "from": ACCOUNT_ADDRESS,
        "nonce": nonce,
        "gas": 600000,
        "type": 2,
        "maxFeePerGas": Web3.to_wei("2", "gwei"),
        "maxPriorityFeePerGas": Web3.to_wei("1", "gwei"),
    })

def confirm_audit_step(prev_len: int, machine_name: str):
    new_len=audit_trail.functions.getAuditTrailLength().call()
    if new_len != prev_len +1:
        raise Exception(f"Missing audit record after {machine_name}: length was {prev_len} and now is {new_len}") 

def calculate_record_hash(machine_address, output_hash, timestamp, previous_hash):
    return Web3.keccak(Web3.solidity_keccak(
        ['address', 'bytes32', 'uint256', 'bytes32'],
        [machine_address, output_hash, timestamp, previous_hash]
    ))

def start_workflow():
    try:
        logging.info("Workflow initiation started by orchestrator.")
        
        #1 start machine 1 (Data acquisition)
        try:
            logging.info("Machine 1 started.")
            prev=audit_trail.functions.getAuditTrailLength().call()
            response1=requests.post(MACHINE1_URL, verify=False)
            response1.raise_for_status()
            confirm_audit_step(prev, "Machine 1")
            logging.info("Machine 1 executed successfully.")
        except Exception as e:
            logging.error(f"Machine 1 failed: {e}", exc_info=True)
            raise Exception("Workflow stopped: Machine 1 failed")
        
        #2 start machine 2 (Anonymization)
        try:
            logging.info("Machine 2 started.")
            prev=audit_trail.functions.getAuditTrailLength().call()
            response2=requests.post(MACHINE2_URL, verify=False)
            response2.raise_for_status()
            confirm_audit_step(prev, "Machine 2")
            logging.info("Machine 2 executed successfully.")
        except Exception as e:
            logging.error(f"Machine 2 failed: {e}", exc_info=True)
            raise Exception("Workflow stopped: Machine 2 failed")
        
        #3 start machine 3 (Analysis)
        try:
            logging.info("Machine 3 started.")
            prev=audit_trail.functions.getAuditTrailLength().call()
            response3=requests.post(MACHINE3_URL, verify=False)
            response3.raise_for_status()
            confirm_audit_step(prev, "Machine 3")
            logging.info("Machine 3 executed successfully.")
        except Exception as e:
            logging.error(f"Machine 3 failed: {e}", exc_info=True)
            raise Exception("Workflow stopped: Machine 3 failed")
        
        #4 start machine 4 (Decision suggestion)
        try:
            logging.info("Machine 4 started.")
            prev=audit_trail.functions.getAuditTrailLength().call()
            response4=requests.post(MACHINE4_URL, verify=False)
            response4.raise_for_status()
            confirm_audit_step(prev, "Machine 4")
            logging.info("Machine 4 executed successfully.")
        except Exception as e:
            logging.error(f"Machine 4 failed: {e}", exc_info=True)
            raise Exception("Workflow stopped: Machine 4 failed")
        
        logging.info("Workflow completed successfully.")
        upload_log_to_gcs()
        return jsonify({"status":"processing done"}), 200
    
    except Exception as e:
        logging.error(f"Workflow aborted. Error during process: {e}", exc_info=True)
        try:
            upload_log_to_gcs()
        except Exception as upload_err:
            logging.error(f"Failed to upload error log: {upload_err}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route("/start", methods=["POST"])
def trigger_workflow():
    return start_workflow()

def upload_log_to_gcs():
    try:
        log_blob_name = f"logs/{os.path.basename(LOG_PATH)}"
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(log_blob_name)
        blob.upload_from_filename(LOG_PATH)
        logging.info(f"Uploaded log file to GCS at: gs://{BUCKET_NAME}/{log_blob_name}")
    except Exception as e:
        logging.error(f"Failed to upload log file to GCS: {e}", exc_info=True)
            
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=("orchestrator.crt","orchestrator.key"))
    