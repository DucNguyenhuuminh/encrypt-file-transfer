from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_data(data: bytes, pvt_key_path: str) -> bytes:
    with open(pvt_key_path, "rb") as key_file:
        pvt_key = serialization.load_pem_private_key(key_file.read(), password=None)
        
    signature = pvt_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature