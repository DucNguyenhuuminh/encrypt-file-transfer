import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair(prefix):
    pvt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    pvt_filename = f"{prefix}_pvt.pem"
    with open(pvt_filename, "wb") as f:
        f.write(pvt_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    pbl_key = pvt_key.public_key()
    pbl_filename = f"{prefix}_pbl.pem"
    with open(pbl_filename, "wb") as f:
        f.write(pbl_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    print(f"Initialized key pairs: {pvt_filename} và {pbl_filename}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        generate_key_pair(sys.argv[1])
    else:
        print("Using: python gen_key.py <prefix_name>")