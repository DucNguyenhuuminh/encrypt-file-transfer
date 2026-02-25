from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

def encrypt_data(data: bytes, receiver_pbl_key_path: str):
    session_key = Fernet.generate_key()
    fernet = Fernet(session_key)
    encrypted_data = fernet.encrypt(data)
    
    with open(receiver_pbl_key_path, "rb") as f:
        receiver_pbl_key = serialization.load_pem_public_key(f.read())
        
    encrypted_session_key = receiver_pbl_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_data, encrypted_session_key

def decrypt_data(encrypted_data: bytes, encrypted_session_key: bytes, receiver_pvt_key_path: str) -> bytes:
    with open(receiver_pvt_key_path, "rb") as f:
        receiver_pvt_key = serialization.load_pem_private_key(f.read(), password=None)
        
    session_key = receiver_pvt_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    fernet = Fernet(session_key)
    original_data = fernet.decrypt(encrypted_data)
    
    return original_data