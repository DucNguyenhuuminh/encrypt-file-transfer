from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def verify_data(data: bytes, signature: bytes, pbl_key_path: str) -> bool:
    try:
        with open(pbl_key_path, "rb") as key_file:
            pbl_key = serialization.load_pem_public_key(key_file.read())
            
        pbl_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False