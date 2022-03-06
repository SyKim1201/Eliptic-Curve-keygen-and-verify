import datetime
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization

certificate_authority_identity = sys.argv[1]
identity_for_certificate = sys.argv[2]

# Import the verification key
try:
    vk_file = open(identity_for_certificate + ".vk", "r")
    vk_lines = vk_file.read()
except:
    raise Exception(".vk file is not formatted correctly")

today = datetime.date.today()

# Hold the body of the certificate as a dictionary. 
# When we print it, we will print it as a json
body = {
    "identity": identity_for_certificate,
    "public key": vk_lines,
    "invalid before": today.isoformat(), # Use isoformat for dates
    "invalid after": (today + datetime.timedelta(days=365)).isoformat(),
    "issuer identity": certificate_authority_identity 
}

# Sign the body of the certificate
# Import the signing key
try:
    sk_file = open(certificate_authority_identity + ".sk", "r")
    sk_lines = sk_file.read()
except:
    raise Exception(".sk file is not formatted correctly")

# Derive the curve and the key from the .sk file
signing_key = serialization.load_pem_private_key(sk_lines.encode('utf-8'), password=None)

# Sign the body of the certificate as a json string with ECDSA and SHA256
# Formatting will have to be the same when verification happens
signature = signing_key.sign(json.dumps(body, sort_keys=True).encode('utf-8'), ec.ECDSA(hashes.SHA256()))

# Construct the certificate as the body & the signature
certificate = {
    "body": body,
    "signature": decode_dss_signature(signature)
}

sys.stdout.write(json.dumps(certificate, indent=4))
sys.stdout.write('\n')
