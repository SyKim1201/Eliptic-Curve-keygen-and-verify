import os
import sys
from cryptography.hazmat.primitives.asymmetric import ec 
from cryptography.x509 import ObjectIdentifier
from cryptography.hazmat.primitives import serialization

# Default choice for curve, but this can be changed
# to any valid curve
curve = ec.SECP384R1()

# Whose key is this?
identity = sys.argv[1]

# Generate key pair
signing_key = ec.generate_private_key(curve)
verification_key = signing_key.public_key()

# Create files for keys

# First check to see if files for the keys already exist
sk_filename = identity + ".sk"
vk_filename = identity + ".vk"

if os.path.exists(sk_filename) or os.path.exists(vk_filename):
    raise Exception("One or more key files already exists for that identity")

# Create files
sk_file = open(sk_filename, "w")
vk_file = open(vk_filename, "w")

# Write the signing key value to sk_file
sk_file.write(signing_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8'))

# Write public values to pk_file
vk_file.write(verification_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8'))

sk_file.close()
vk_file.close()
