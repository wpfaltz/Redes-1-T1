import json
import os
import socket
import re
import base64
import hashlib
from cryptography.fernet import Fernet

# Generates a valid 32 bytes key based on the string 'qweasd' and converts to Base64
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)

def validate_nickname(nickname: str) -> bool:
    """Verifica se o nickname contém apenas letras minúsculas e números, sem espaços ou caracteres especiais."""
    return bool(re.match("^[a-z0-9]+$", nickname))

def create_user(nickname:str, senha: str) -> int:
    """Cria um usuário com o nickname e senha fornecidos, verificando se o usuário já existe."""
    # Verify if nickname is valid
    if not validate_nickname(nickname):
        return 0  # Invalid User

    # 'id' folder path
    folder_path = os.path.join(os.getcwd(), "id")
    
    # Create folder 'id' if it doesn't exist
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    # Verify if the user already exists
    file_path = os.path.join(folder_path, f"{nickname}.json")
    if os.path.isfile(file_path):
        return 3  # User already exists
    
    # Creation of JSON file for the user
    user_data = {
        "User": nickname,
        "Pass": senha
    }
    
    with open(file_path, "w") as json_file:
        json.dump(user_data, json_file)
    
    return 1  # Successfully created user

def receivement(user, password, flag, *args):
    if flag == 0:
        file_path = os.path.join("id", f"{user}.json")
        if not os.path.isfile(file_path):
            return 1
        with open(file_path, "r") as file:
            user_data = json.load(file)
            if user_data.get("User") != user or user_data.get("Pass") != password:
                return 0
        return user_data

    elif flag == 1:
        sender, recipient, email_content = user, args[0], args[1]
        file_path = os.path.join("id", f"{recipient}.json")
        if not os.path.isfile(file_path):
            return 0
        with open(file_path, "r") as file:
            recipient_data = json.load(file)
        new_message = {
            "id": sender,
            "message": email_content
        }
        if "Email" in recipient_data:
            recipient_data["Email"].append(new_message)
        else:
            recipient_data["Email"] = [new_message]
        with open(file_path, "w") as file:
            json.dump(recipient_data, file, indent=4)
        return 1

    elif flag == 3:
        nickname = user
        senha = password
        return create_user(nickname, senha)

    return None

def start_server():
    HOST = '0.0.0.0'
    PORT = 7444
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        
        while True:
            conn, addr = server_socket.accept()
            with conn:
                try:
                    # Receives message length
                    encrypted_length = int(conn.recv(10).decode().strip())
                    encrypted_data = conn.recv(encrypted_length)
                    
                    # decrypts the data received
                    data = cipher_suite.decrypt(encrypted_data).decode()
                    request = json.loads(data)
                    
                    flag = request.get("flag")
                    
                    if flag == 0:
                        user = request.get("User")
                        password = request.get("Pass")
                        response = receivement(user, password, flag)
                    elif flag == 1:
                        user = request.get("User")
                        recipient = request.get("recipient")
                        email_content = request.get("email_content")
                        response = receivement(user, None, flag, recipient, email_content)
                    elif flag == 3:
                        user = request.get("User")
                        password = request.get("Pass")
                        response = receivement(user, password, flag)
                    else:
                        response = {"Error": "Invalid flag"}
                    
                    # Serializes the answer and encrypt it before sending
                    response_data = json.dumps(response)
                    encrypted_response = cipher_suite.encrypt(response_data.encode())
                    response_length = f"{len(encrypted_response):<10}"
                    conn.sendall(response_length.encode() + encrypted_response)
                
                except json.JSONDecodeError:
                    error_response = {"Error": "Invalid data"}
                    encrypted_error = cipher_suite.encrypt(json.dumps(error_response).encode())
                    conn.sendall(f"{len(encrypted_error):<10}".encode() + encrypted_error)
                except Exception:
                    error_response = {"Error": "Internal server error"}
                    encrypted_error = cipher_suite.encrypt(json.dumps(error_response).encode())
                    conn.sendall(f"{len(encrypted_error):<10}".encode() + encrypted_error)

if __name__ == "__main__":
    start_server()
