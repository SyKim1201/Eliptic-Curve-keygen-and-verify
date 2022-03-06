import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization


# Who is doing the signing?
identity = sys.argv[1]

# Import the signing key
try:
    sk_file = open(identity + ".sk", "r")
    sk_lines = sk_file.read()
except:
    raise Exception(".sk file is not formatted correctly")

# Derive the curve and the key from the .sk file
signing_key = serialization.load_pem_private_key(sk_lines.encode('utf-8'), password=None)

# Grab the contents of stdin to be signed
message = "".join(sys.stdin.read()).encode('utf-8')

# Sign the message
signature = signing_key.sign(message, ec.ECDSA(hashes.SHA256()))

# Return the signature to stdout
(r,s) = decode_dss_signature(signature)

sys.stdout.write(str(r))
sys.stdout.write('\n')
sys.stdout.write(str(s))
sys.stdout.write('\n')
