import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import logging
import time
import os
import time
import sys
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify
import pandas as pd
import requests
import ipaddress
from google.cloud import kms_v1, storage
from web3 import Web3
import socket, http.client
from eth_account import Account
from google.cloud import logging as cloud_logging
from google.cloud.logging_v2.handlers import CloudLoggingHandler

app = Flask(__name__)

MACHINE_ID="machine-04-decision-suggestion"
external_ip = os.getenv("EXTERNAL_IP", "34.141.125.168")
BUILD_HASH=os.getenv("BUILD_HASH","unknown")
TEST_MODE=os.getenv("TEST_MODE", "normal")
SKIP_ATTESTATION = os.getenv("SKIP_ATTESTATION", "true").lower() == "true"

timestamp = datetime.now(timezone.utc).isoformat().replace(":", "_")
LOG_PATH = os.path.join(f"{MACHINE_ID}_{timestamp}.log")
cloud_client=cloud_logging.Client()
cloud_handler=CloudLoggingHandler(cloud_client, name="machine-1-logs")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout),
        cloud_handler
    ]
)

logging.info(f"Machine started with mode: {TEST_MODE}")
logging.info(f"Build Hash: {BUILD_HASH}")
ORCHESTRATOR_URL=os.getenv("ORCHESTRATOR_URL","https://34.107.97.43:5000")
FIXED_STEP_NUMBER=4
BUCKET_NAME=os.getenv("BUCKET_NAME","machine-04-bucket")

TLS_CERT_LOCAL_PATH = f"/tmp/{MACHINE_ID}_cert.pem"
TLS_KEY_LOCAL_PATH = f"/tmp/{MACHINE_ID}.pem"
TLS_CERT_GCS_PATH = f"{MACHINE_ID}/tls_cert.pem"
TLS_KEY_GCS_PATH = f"{MACHINE_ID}/tls_key.pem"

ETH_KEY_FILE_GCS = f"{MACHINE_ID}/eth_key.bin"
ETH_KEY_LOCAL = "/tmp/eth_key_encrypted.bin"

storage_client=storage.Client()
kms_client = kms_v1.KeyManagementServiceClient()

KMS_KEY_OWN_NAME = "projects/machine-04-decision-suggestion/locations/global/keyRings/machine-4-keyring/cryptoKeys/machine-4-key"
KMS_KEY_PREVIOUS_NAME = "projects/machine-03-data-analysis/locations/global/keyRings/machine-3-keyring/cryptoKeys/machine-3-key"


def request_latest_audit_record():
    response = requests.get(f"{ORCHESTRATOR_URL}/get_latest_audit",verify=False)
    response.raise_for_status()

    data=response.json()
    gcs_url=data["gcs_url"]
    expected_output_hash=data["output_hash"]
    
    logging.info(f"Received GCS URL:{gcs_url}")
    logging.debug(f"Expected hash: {expected_output_hash}")
    
    return gcs_url, expected_output_hash

def verify_hash(local_hash, expected_hash):
    import logging

    logging.info("Verifying input hash...")

    logging.debug(f"Local hash (type: {type(local_hash)}, len: {len(local_hash)}): {local_hash}")
    logging.debug(f"Expected hash (type: {type(expected_hash)}, len: {len(expected_hash)}): {expected_hash}")

    try:
        local_bytes = local_hash.encode('utf-8')
        expected_bytes = expected_hash.encode('utf-8')
        logging.debug(f"Local bytes: {local_bytes.hex()}")
        logging.debug(f"Expected bytes: {expected_bytes.hex()}")
    except Exception as e:
        logging.warning(f"Could not encode hashes for hexdump: {str(e)}")

    # Normalize both hashes: strip, lowercase, and remove '0x' if present
    def normalize(h):
        return h.strip().lower().removeprefix("0x")

    normalized_local = normalize(local_hash)
    normalized_expected = normalize(expected_hash)

    logging.debug(f"Normalized local: {normalized_local}")
    logging.debug(f"Normalized expected: {normalized_expected}")

    if normalized_local != normalized_expected:
        # Find the first differing character
        diff_pos = next((i for i, (l, e) in enumerate(zip(normalized_local, normalized_expected)) if l != e), None)

        if diff_pos is not None:
            logging.error(f"Hashes differ at position {diff_pos}:")
            logging.error(f"Local: ...{normalized_local[max(0,diff_pos-5):diff_pos+5]}...")
            logging.error(f"Expect: ...{normalized_expected[max(0,diff_pos-5):diff_pos+5]}...")

        logging.warning("Hash mismatch detected! Possible data tampering")
        raise ValueError("Hash mismatch! Data integrity compromised.")

    logging.info("Hash verified successfully. Data integrity intact.")

def calculate_output_hash(file_path):
    logging.info("Calculating output hash...")
    with open(file_path, "rb") as f:
        file_bytes=f.read()
    output_hash= hashlib.sha256(file_bytes).hexdigest()
    logging.debug(f"Output hash: {output_hash}")
    return output_hash

def download_file_from_gcs(gcs_url):
    logging.info(f"Downloading encrypted file from {gcs_url}")
    
    #bucket + blob from url
    parsed_url=urlparse(gcs_url)
    path_parts=parsed_url.path.lstrip("/").split("/",1)
    bucket_name=path_parts[0]
    blob_name=path_parts[1]
    
    bucket = storage_client.bucket(bucket_name)
    blob=bucket.blob(blob_name)
    
    #file name based on original
    original_filename=os.path.basename(blob_name)
    local_encrypted_path=f"/tmp/{original_filename}"
    
    blob.download_to_filename(local_encrypted_path)
    logging.info(f"Encrypted file downloaded to {local_encrypted_path}")
    
    return local_encrypted_path, bucket_name, original_filename

def decrypt_file(local_encrypted_path):
    logging.info("Decrypting file with KMS...")
    try:
        with open(local_encrypted_path, "r") as f:
            package = json.load(f)

        iv = base64.b64decode(package["iv"])
        encrypted_key = base64.b64decode(package["encrypted_key"])
        ciphertext = base64.b64decode(package["ciphertext"])

        response = kms_client.decrypt(
            request={"name": KMS_KEY_PREVIOUS_NAME, "ciphertext": encrypted_key}
        )
        aes_key = response.plaintext

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        local_decrypted_path = local_encrypted_path.replace(".json", "_decrypted.json")
        with open(local_decrypted_path, "wb") as f:
            f.write(decrypted_bytes)

        logging.info(f"Decrypted file saved at {local_decrypted_path}")
        return local_decrypted_path

    except Exception as e:
        logging.error("Decryption failed.", exc_info=True)
        raise ValueError("Hybrid decryption failed") from e


def process_data(local_decrypted_path):
    logging.info("Processing dataset...")
    with open(local_decrypted_path, "r") as f:
        data=json.load(f)
        
    df = pd.DataFrame(data)
    logging.info("Before machine 4 computation: first 10 rows:\n%s", df.head(10).to_string())
    
    #suggest decision based on prediction/outcome
    if "Outcome" in df.columns:
        df["Risk_Level"] = df["Outcome"].apply(lambda x: "High Risk" if x == 1 else "Low Risk")
    else:
        return ValueError({"error": "Outcome column missing"})
    logging.info("After machine 4 computation: first 10 rows:\n%s", df.head(10).to_string())
      
    local_processed_path=local_decrypted_path.replace("_decrypted.json", "_processed.json")
    df.to_json(local_processed_path, orient="records")
    logging.info(f"Processed dataset saved at {local_processed_path}")
    return local_processed_path

def encrypt_processed_file(local_processed_path):
    logging.info("Encrypting processed output...")
    with open(local_processed_path, "rb") as f:
        file_bytes = f.read()

    # AES key + IV erzeugen
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()

    response = kms_client.encrypt(
        request={"name": KMS_KEY_OWN_NAME, "plaintext": aes_key}
    )
    encrypted_aes_key = response.ciphertext

    package = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_aes_key).decode()
    }

    local_encrypted_output = local_processed_path.replace("_processed.json", f"_{FIXED_STEP_NUMBER}.json")
    with open(local_encrypted_output, "w") as f:
        json.dump(package, f)

    logging.info(f"Hybrid-encrypted output saved at {local_encrypted_output}")
    return local_encrypted_output

def upload_encrypted_output(encrypted_output_path, original_filename,fixed_step_number):
    logging.info("Uploading encrypted processed file to GCS...")
    
    bucket=storage_client.bucket(BUCKET_NAME)
    
    #new file name
    base_name, ext = os.path.splitext(original_filename)
    new_blob_name=f"results/{base_name}_{fixed_step_number}.bin"
    
    blob = bucket.blob(new_blob_name)
    blob.upload_from_filename(encrypted_output_path)
    
    public_url=f"https://storage.googleapis.com/{BUCKET_NAME}/{new_blob_name}"
    logging.info(f"Encryped file uploaded to {public_url}")
    
    return public_url


def sign_output_hash(output_hash_hex:str)->str:
    logging.info(f"Signing hash: {output_hash_hex}")

    key_path=TLS_KEY_LOCAL_PATH

    if not os.path.exists(key_path):
        raise FileNotFoundError(f"TLS key not found at: {key_path}")        
        
    with open(key_path, "rb") as key_file:
        private_key=serialization.load_pem_private_key(key_file.read(), password=None)
    
    #hash to bytes
    output_hash_bytes=bytes.fromhex(output_hash_hex)
    
    logging.debug(f"output_hash_bytes: {output_hash_bytes.hex()} ({len(output_hash_bytes)} bytes)")
    signature=private_key.sign(
        output_hash_bytes,
        padding.PKCS1v15(),
        Prehashed(hashes.SHA256())
    )
    logging.info(f"Generated signature: {signature[:20]}...")
    return base64.b64encode(signature).decode("utf-8")

def get_registration_nonce() -> dict:
    #Retrieve registration nonce from orchestrator
    response = requests.post(
        f"{ORCHESTRATOR_URL}/get_registration_nonce",
        json={"machine_address": ETH_ADDRESS},
        verify=False,
        timeout=5
    )
    response.raise_for_status()
    logging.info(f"Registration nonce response: {response.text}")
    return response.json()

def get_audit_nonce() -> dict:
    #Retrieve registration nonce from orchestrator
    response = requests.post(
        f"{ORCHESTRATOR_URL}/get_audit_nonce",
        json={"machine_address": ETH_ADDRESS},
        verify=False,
        timeout=5
    )
    response.raise_for_status()
    logging.info(f"Audit nonce response: {response.text}")
    return response.json()

def get_audit_nonce() -> dict:
    #Retrieve registration nonce from orchestrator
    response = requests.post(
        f"{ORCHESTRATOR_URL}/get_audit_nonce",
        json={"machine_address": ETH_ADDRESS},
        verify=False,
        timeout=5
    )
    response.raise_for_status()
    logging.info(f"Audit nonce response: {response.text}")
    return response.json()

def fetch_attestation(nonce: str) -> str:
    # open unix‐domain socket to the TEE attestation server
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(30)  
    sock.connect("/run/container_launcher/teeserver.sock")
    conn = http.client.HTTPConnection("localhost")
    conn.sock = sock

    #build and send request
    body = json.dumps({
        "audience": "orchestrator011551155",
        "token_type": "OIDC",
        "nonces": [nonce]
    })
    conn.request(
        method="POST",
        url="/v1/token",
        body=body,
        headers={"Content-Type": "application/json"}
    )

    #read the HTTP response, get raw token
    resp = conn.getresponse()
    raw_token = resp.read().decode("utf-8")

    #clean up
    conn.close()
    sock.close()

    #the body of the HTTP response *is* the JWT string
    return raw_token

def submit_audit_record(output_hash, public_url):
    try:
        logging.info("Submitting audit record for machine 4...")
        
        nonce = get_audit_nonce()["nonce"]

        if SKIP_ATTESTATION:
            logging.warning("SKIP_ATTESTATION=true. using dummy attestation token")
            attestation_token = "dummy_attestation_token"
        else:
            logging.warning("SKIP_ATTESTATION=false: fetching real attestation token")
            attestation_token = fetch_attestation(nonce)
            
        blob_name=f"attestations/submit_audit/{MACHINE_ID}_from{datetime.now(timezone.utc).isoformat()}.jwt"
        bucket=storage_client.bucket(BUCKET_NAME)
        blob=bucket.blob(blob_name)
        blob.upload_from_string(
            attestation_token
        )       
        signature=sign_output_hash(output_hash)
        payload={
            "machine_address": ETH_ADDRESS,
            "output_hash": output_hash,
            "signature":signature,
            "gcs_url": public_url,
            "attestation_token":attestation_token,
            "build_hash": BUILD_HASH,
            "nonce":nonce,
            "step":FIXED_STEP_NUMBER
        }
        logging.debug(f"Audit payload: {json.dumps(payload, indent=2)}")
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{ORCHESTRATOR_URL}/submit_audit",
                    json=payload,
                    verify=False,
                    timeout=10
                )
                response.raise_for_status()
                logging.info("Audit successfully submitted")
                return
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    raise
                logging.warning(f"Attempt {attempt + 1} failed, retrying...")
                time.sleep(2 ** attempt)
    except Exception as e:
        logging.error(f"Failed to submit audit: {str(e)}", exc_info=True)
        raise
    
@app.route('/decision', methods=['POST'])
def handle_process():
    try:
        logging.info("Machine 4 process started...")

        #0 register machine
        register_machine()
        
        #1 get audit record
        gcs_url, expected_output_hash = request_latest_audit_record()
        
        #2 download file
        local_encrypted_path, bucket_name, original_filename= download_file_from_gcs(gcs_url)
        
        #3 decrypt file
        local_decrypted_path=decrypt_file(local_encrypted_path)
        
        #4 hash of file
        local_hash =calculate_output_hash(local_decrypted_path)
        
        #5 verify hash
        verify_hash(local_hash, expected_output_hash)
        
        #6 process data
        local_processed_path=process_data(local_decrypted_path)
        
        #7 calculate outputHash for audit trail record
        output_hash= calculate_output_hash(local_processed_path)
        
        #8 encrypt 
        local_encrypted_path = encrypt_processed_file(local_processed_path)
        
        #9 upload
        public_url= upload_encrypted_output(local_encrypted_path, original_filename, FIXED_STEP_NUMBER)
        
        #10 new audit record
        submit_audit_record(output_hash, public_url)
        
        logging.info("Machine 4 process completed successfully")
        upload_log_to_gcs()
        return jsonify({"status":"processing done"}), 200
    
    except Exception as e:
        logging.error(f"Error during process: {e}", exc_info=True)
        try:
            upload_log_to_gcs()
        except Exception as upload_err:
            logging.error(f"Failed to upload error log: {upload_err}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    
def generate_tls_certificate(machine_cn: str=MACHINE_ID):
    private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject=x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, machine_cn)
    ])
    
    cert_builder=(
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(MACHINE_ID),
                x509.IPAddress(ipaddress.IPv4Address(external_ip))  
        ]), 
        critical=False
                       )
    )
    
    cert = cert_builder.sign(private_key, hashes.SHA256())
    
    cert_pem=cert.public_bytes(serialization.Encoding.PEM)
    key_pem=private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(TLS_CERT_LOCAL_PATH, "wb") as f:
        f.write(cert_pem)
        
    with open(TLS_KEY_LOCAL_PATH, "wb") as f:
        f.write(key_pem)
        
    public_key_bytes=private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_hash=hashlib.sha256(public_key_bytes).hexdigest()
    
    return  public_key_hash, cert_pem

def calculate_public_key_hash(cert_pem: bytes):
    cert=x509.load_pem_x509_certificate(cert_pem)
    public_key_bytes=cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) 
    return hashlib.sha256(public_key_bytes).hexdigest()
        

def is_already_registered():
    try:
        logging.info(f"Checking if machine is already registered with orchestrator at {ORCHESTRATOR_URL}")
        
        response=requests.post(f"{ORCHESTRATOR_URL}/is_machine_registered", json={
            "machine_address": ETH_ADDRESS
        },verify=False)
        
        response.raise_for_status()
        is_active = response.json().get("active", False)
        
        if is_active:
            logging.info(f"Machine {ETH_ADDRESS} is already registered.")
        else:
            logging.info(f"Machine {ETH_ADDRESS} is not registered.")
        
        return is_active
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking registration status for {ETH_ADDRESS}: {e}", exc_info=True)
        raise Exception(f"Failed to check registration status for machine {ETH_ADDRESS}: {e}")

def register_machine():
    try:
        logging.info(f"Starting registration with orchestrator at {ORCHESTRATOR_URL}")
        if is_already_registered():
            logging.info("Machine already registered. Skipping re-registration")
            cert_pem = open(TLS_CERT_LOCAL_PATH, "rb").read()
            public_key_hash = calculate_public_key_hash(cert_pem)

            sync_payload = {
                "machine_address": ETH_ADDRESS,
                "certificate_pem": base64.b64encode(cert_pem).decode("utf-8"),
                "build_hash": BUILD_HASH,
            }

            try:
                response = requests.post(
                    f"{ORCHESTRATOR_URL}/sync_metadata",
                    json=sync_payload,
                    verify=False
                )
                response.raise_for_status()
                logging.info(f"Metadata sync response: {response.text}")
            except Exception as e:
                logging.error(f"Metadata sync failed: {e}", exc_info=True)
            return
        if not os.path.exists(TLS_KEY_LOCAL_PATH):
            public_key_hash, cert_pem=generate_tls_certificate(MACHINE_ID)
        else:
            cert_pem=open(TLS_CERT_LOCAL_PATH, "rb").read()
            public_key_hash=calculate_public_key_hash(cert_pem)
        
        #get nonce from orchestrator
        logging.info("Requesting registration nonce from orchestrator...")
        nonce_response = get_registration_nonce()
        nonce = nonce_response["nonce"]
        
        # create attestation
        if SKIP_ATTESTATION:
            logging.warning("SKIP_ATTESTATION=true")
            attestation_token = "dummy_attestation_token"
        else:
            logging.warning("SKIP_ATTESTATION=false: fetching real attestation token")
            attestation_token = fetch_attestation(nonce)
            logging.info("Attestation token successfully fetched.")
            logging.debug(f"Attestation token snippet: {attestation_token[:100]}...")
            
        blob_name=f"attestations/registration/{MACHINE_ID}_from{datetime.now(timezone.utc).isoformat()}.jwt"
        bucket=storage_client.bucket(BUCKET_NAME)
        blob=bucket.blob(blob_name)
        blob.upload_from_string(
            attestation_token
        )
        #registering
        logging.info("Submitting registration...")
        response = requests.post(f"{ORCHESTRATOR_URL}/register_machine", json={
            "machine_address": ETH_ADDRESS,
            "public_key_hash": public_key_hash,
            "attestation_token": attestation_token,
            "certificate_pem": base64.b64encode(cert_pem).decode("utf-8"),
            "build_hash": BUILD_HASH,
            "step": FIXED_STEP_NUMBER,
            "nonce":nonce
        },verify=False)
        
        response.raise_for_status()
        result=response.json()
        logging.info(f"Registering successful: TX={result.get('tx_hash')}")
        
    except Exception as e:
        logging.error(f"Error registering: {e}", exc_info=True)
        
def load_or_create_eth_key():
    global ETH_PRIVATE_KEY, ETH_ADDRESS
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(ETH_KEY_FILE_GCS)

    if blob.exists():
        logging.info("Encrypted Ethereum key found in GCS. Downloading...")
        blob.download_to_filename(ETH_KEY_LOCAL)

        with open(ETH_KEY_LOCAL, "rb") as f:
            encrypted_bytes = f.read()

        response = kms_client.decrypt(
            request={"name": KMS_KEY_OWN_NAME, "ciphertext": encrypted_bytes}
        )
        decrypted_key = response.plaintext.decode()

        eth_account = Account.from_key(decrypted_key)
        ETH_PRIVATE_KEY = eth_account.key.hex()
        ETH_ADDRESS = eth_account.address
        logging.info(f"Recovered Ethereum identity: {ETH_ADDRESS}")

    else:
        logging.info("No ETH key found in GCS – generating new key...")
        eth_account = Account.create()
        ETH_PRIVATE_KEY = eth_account.key.hex()
        ETH_ADDRESS = eth_account.address

        # Encrypt private key with KMS
        response = kms_client.encrypt(
            request={"name": KMS_KEY_OWN_NAME, "plaintext": ETH_PRIVATE_KEY.encode()}
        )
        encrypted_key = response.ciphertext

        # Save encrypted key to GCS
        with open(ETH_KEY_LOCAL, "wb") as f:
            f.write(encrypted_key)

        blob.upload_from_filename(ETH_KEY_LOCAL)
        logging.info(f"Generated and stored ETH key for {ETH_ADDRESS}")

def load_or_create_tls_certificate():
    bucket = storage_client.bucket(BUCKET_NAME)
    cert_blob = bucket.blob(TLS_CERT_GCS_PATH)
    key_blob = bucket.blob(TLS_KEY_GCS_PATH)

    if cert_blob.exists() and key_blob.exists():
        logging.info("TLS certificate and key found in GCS. Downloading...")
        cert_blob.download_to_filename(TLS_CERT_LOCAL_PATH)
        key_blob.download_to_filename(TLS_KEY_LOCAL_PATH)
        logging.info("TLS cert and key loaded from GCS.")
    else:
        logging.info("TLS certificate not found in GCS – generating new certificate...")
        public_key_hash, cert_pem = generate_tls_certificate(MACHINE_ID)

        cert_blob.upload_from_filename(TLS_CERT_LOCAL_PATH)
        key_blob.upload_from_filename(TLS_KEY_LOCAL_PATH)
        logging.info("Generated and stored TLS certificate and key in GCS.")


def verify_tls_key_matches_cert():
    try:
        with open(TLS_CERT_LOCAL_PATH, "rb") as cert_file, open(TLS_KEY_LOCAL_PATH, "rb") as key_file:
            cert = x509.load_pem_x509_certificate(cert_file.read())
            key = serialization.load_pem_private_key(key_file.read(), password=None)

        pub_cert = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if pub_cert == pub_key:
            logging.info("TLS key and certificate MATCH")
        else:
            logging.error("TLS key and certificate DO NOT MATCH")
    except Exception as e:
        logging.error(f"TLS key-cert check failed: {e}", exc_info=True)

def upload_log_to_gcs():
    try:
        log_blob_name = f"logs/{os.path.basename(LOG_PATH)}"
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(log_blob_name)
        blob.upload_from_filename(LOG_PATH)
        logging.info(f"Uploaded log file to GCS at: gs://{BUCKET_NAME}/{log_blob_name}")
    except Exception as e:
        logging.error(f"Failed to upload log file to GCS: {e}", exc_info=True)


if __name__ == "__main__":
    load_or_create_tls_certificate()
    verify_tls_key_matches_cert()
    load_or_create_eth_key()

    app.run(host="0.0.0.0", port=5000, ssl_context=(TLS_CERT_LOCAL_PATH, TLS_KEY_LOCAL_PATH))

