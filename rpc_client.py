import sys
import xmlrpc.client
import os
import sign
import encrypt

CLIENT_PRIVATE_KEY = "client_pvt.pem"
SERVER_PUBLIC_KEY = "server_pbl.pem"
RPC_SERVER_URL = "http://127.0.0.1:9000/"

def send_file(file_path: str):
    if not os.path.exists(file_path):
        print("File not found!")
        return
        
    filename = os.path.basename(file_path)
    
    with open(file_path, "rb") as f:
        file_data = f.read()

    signature = sign.sign_data(file_data, CLIENT_PRIVATE_KEY)
    enc_data, enc_session_key = encrypt.encrypt_data(file_data, SERVER_PUBLIC_KEY)
    proxy = xmlrpc.client.ServerProxy(RPC_SERVER_URL)
    
    response = proxy.upload_file(
        filename,
        xmlrpc.client.Binary(enc_data),
        xmlrpc.client.Binary(enc_session_key),
        xmlrpc.client.Binary(signature)
    )
    
    print("Response from Server:", response)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        send_file(sys.argv[1])
    else:
        print("Using: python rpc_client.py <file_name>")