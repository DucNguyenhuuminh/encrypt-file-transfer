# rpc_server.py
from xmlrpc.server import SimpleXMLRPCServer
import os
import encrypt
import verify

SERVER_PRIVATE_KEY = "server_pvt.pem"
CLIENT_PUBLIC_KEY = "client_pbl.pem"
UPLOAD_DIR = "received_files"

os.makedirs(UPLOAD_DIR, exist_ok=True)

def upload_file(filename: str, enc_data_bin, enc_session_key_bin, signature_bin):
    try:
        enc_data = enc_data_bin.data
        enc_session_key = enc_session_key_bin.data
        signature = signature_bin.data
        print(f"Handling received file: {filename}...")
        
        original_data = encrypt.decrypt_data(enc_data, enc_session_key, SERVER_PRIVATE_KEY)
        is_valid = verify.verify_data(original_data, signature, CLIENT_PUBLIC_KEY)
        if not is_valid:
            return "ERROR: Invalid signature. File could be fake"
            
        save_path = os.path.join(UPLOAD_DIR, filename)
        with open(save_path, "wb") as f:
            f.write(original_data)
        return f"SUCCESS: File {filename} have been verified and saved"
        
    except Exception as e:
        return f"ERROR: {str(e)}"

if __name__ == "__main__":
    server = SimpleXMLRPCServer(("0.0.0.0", 9000), allow_none=True)
    print("Server listen at port 9000")
    
    server.register_function(upload_file, "upload_file")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer end")