#sy63kim
#A5Q1a

from datetime import date
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import serialization

ca_identity = sys.argv[1]
signer_identity = sys.argv[2]

# Load the CA key
with open(ca_identity + ".vk", "r") as ca_file:
    ca_lines = ca_file.read()
    ca_public_key = serialization.load_pem_public_key(ca_lines.encode('utf-8'))

# Load the signer's cert
with open(signer_identity + "/" + signer_identity + ".cert", "r") as cert_file:
    cert = json.load(cert_file)

# Load the message and signature
with open(signer_identity + "/message.txt", "r") as msg_file:
    message = "".join(msg_file.readlines()).encode('utf-8')
with open(signer_identity + "/signature.txt", "r") as sig_file:
    signature_r = int(sig_file.readline())
    signature_s = int(sig_file.readline())

# Continue your solution here

# Check identity of signer
if cert["body"]["identity"] != signer_identity:
    print("signer identity invalid")

# Check identity of issuer
if cert["body"]["issuer identity"] != ca_identity:
    print("issuer identity invalid")

# Check issue date
before = date.fromisoformat(cert["body"]["invalid before"])
after = date.fromisoformat(cert["body"]["invalid after"])
today = date.today()
if before > today or after < today:
    print("issue date invalid")

# Verify message
signature = encode_dss_signature(signature_r, signature_s)
public_key = serialization.load_pem_public_key(cert["body"]["public key"].encode('utf-8'))
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
except:
    print("message verification failed")

# Verify issuer
issue_sig = encode_dss_signature(cert["signature"][0], cert["signature"][1])
try:
    ca_public_key.verify(issue_sig, json.dumps(cert["body"], sort_keys=True).encode('utf-8'), ec.ECDSA(hashes.SHA256()))
except:
    print("issuer verification failed")

# Some useful functions you might want to look up:
# - date.fromisoformat in the main Python documentation
# - encode_dss_signature and serialization.load_pem_public_key in Python Cryptography library documentation
