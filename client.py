import tkinter as tk
from tkinter import messagebox
import json
import socket
import base64
import hashlib
from cryptography.fernet import Fernet

# Configuração de criptografia
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)

# Variáveis globais
User = ""
Pass = ""
IP = ""
PORT = 0
open_chats = {}  # Dict for open chats
json_data = {}  # Dict to store the initial JSON received from server

def recv_full_data(sock):
    """Auxiliary function to receive the message length followed by the complete message."""
    try:
        message_length = int(sock.recv(10).decode().strip())
        data = b""
        while len(data) < message_length:
            data += sock.recv(1024)
        return data
    except ValueError:
        return b'{"Error": "Error receiving the data"}'


def send_encrypted_data(data, socket):
    """Encrypts and sends the JSON through socket."""
    encrypted_data = cipher_suite.encrypt(data.encode())
    encrypted_length = f"{len(encrypted_data):<10}"
    socket.sendall(encrypted_length.encode() + encrypted_data)

def send_to_server():
    """Function to send initial login data."""
    global User, Pass, IP, PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORT))
            data = json.dumps({"flag": 0, "User": User, "Pass": Pass})
            send_encrypted_data(data, s)
            
            # Receives full response from server and decrypts it
            response = recv_full_data(s)
            response = cipher_suite.decrypt(response).decode()
            result = json.loads(response)
            
            # Process result
            if result == 0:
                messagebox.showerror("Error", "Incorrect password")
            elif result == 1:
                messagebox.showinfo("Error", "User not found")
            elif isinstance(result, dict):  # JSON received
                global json_data
                json_data = result  # Stores JSON for posterior use
                show_chat_interface()
        
        except json.JSONDecodeError as e:
            messagebox.showerror("Connection error", f"Error decrypting JSON response: {e}")
        except Exception as e:
            messagebox.showerror("Connection error", f"Unable to connect to server: {e}")

def send_create_user():
    """Function that sends create a new user."""
    global User, Pass, IP, PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORT))
            data = json.dumps({"flag": 3, "User": User, "Pass": Pass})
            send_encrypted_data(data, s)
            
            # Receive server response and decrypts it
            response = recv_full_data(s)
            response = cipher_suite.decrypt(response).decode()
            result = json.loads(response)
            
            # Processa o resultado
            if result == 0:
                messagebox.showerror("Error", "Invalid user")
            elif result == 1:
                messagebox.showinfo("Success", "Successfully created user!")
            elif result == 3:
                messagebox.showinfo("Error", "User already exists")
        
        except json.JSONDecodeError as e:
            print("Error decoding received JSON:", e)
            messagebox.showerror("Connection error", f"Error decrypting response JSON: {e}")
        except Exception as e:
            print("Error connecting or receiving data from server:", e)
            messagebox.showerror("Connection error", f"Unable to connect to server: {e}")

def show_chat_interface():
    """Exhibits the chat interface after login."""
    for widget in root.winfo_children():
        widget.destroy()
    
    unique_ids = set(email["id"] for email in json_data.get("Email", []))
    
    # Exhibit the list of unique IDs as buttons to open chats
    tk.Label(root, text="Open chats:").pack()
    for user_id in unique_ids:
        tk.Button(root, text=user_id, command=lambda u=user_id: open_chat(u)).pack()

    tk.Button(root, text="Create New Chat", command=create_chat).pack()

def open_chat(user):
    """Opens a new chat window with the specified user"""
    if user in open_chats:
        return

    chat_window = tk.Toplevel(root)
    chat_window.title(f"Conversa com {user}")

    def close_window():
        chat_window.destroy()
        if user in open_chats:
            del open_chats[user]

    chat_window.protocol("WM_DELETE_WINDOW", close_window)

    # Messages display area
    chat_text = tk.Text(chat_window, height=15, width=50, state="disabled")
    chat_text.pack()

    # Button to refresh messages
    tk.Button(chat_window, text="Refresh", command=lambda: update_messages(user, chat_text)).pack()

    # Message inbox
    msg_entry = tk.Entry(chat_window, width=50)
    msg_entry.pack()

    # Button to send message
    tk.Button(chat_window, text="Enviar", command=lambda: send_message(user, msg_entry)).pack()

    open_chats[user] = (chat_window, chat_text)

    # Load all previous messages from JSON and exhibit
    update_messages(user, chat_text)

def update_messages(user, chat_text):
    """Atualiza as mensagens para um usuário específico ao clicar no botão de atualização."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORT))
            data = json.dumps({"flag": 0, "User": User, "Pass": Pass})  # Solicita as mensagens do usuário
            send_encrypted_data(data, s)
            response = recv_full_data(s)
            response = cipher_suite.decrypt(response).decode()
            messages = json.loads(response).get("Email", [])

            chat_text.config(state="normal")
            chat_text.delete("1.0", tk.END)  # Limpa a caixa de texto antes de adicionar novas mensagens

            for email in messages:
                if email["id"] == user:
                    sender = email["id"]
                    content = email.get("message", "")
                    chat_text.insert(tk.END, f"{sender}: {content}\n")
            chat_text.config(state="disabled")
            chat_text.yview(tk.END)
        except Exception as e:
            print("Error updating message: ", e)

def send_message(user, msg_entry, default_msg=None):
    """Sends message to the specified user"""
    msg_content = default_msg or msg_entry.get().strip()
    if msg_content:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((IP, PORT))
            data = json.dumps({
                "flag": 1,
                "User": User,
                "recipient": user,
                "email_content": msg_content
            })
            send_encrypted_data(data, s)
            response = recv_full_data(s)
            response = cipher_suite.decrypt(response).decode()
            result = json.loads(response)

            # Show sent message on chat window
            if user in open_chats:
                chat_text = open_chats[user][1]
                chat_text.config(state="normal")
                chat_text.insert(tk.END, f"Você: {msg_content}\n")
                chat_text.config(state="disabled")
                chat_text.yview(tk.END)  # Scroll automatically to last message

            if default_msg is None:
                msg_entry.delete(0, tk.END)

def create_chat():
    """Opens a new window to insert the user nickname to start a new chat with."""
    new_chat = tk.Toplevel(root)
    new_chat.title("New Chat")
    
    tk.Label(new_chat, text="Provide the user nickname:").pack()
    user_entry = tk.Entry(new_chat)
    user_entry.pack()

    def start_chat():
        user = user_entry.get().strip()
        if user:
            open_chat(user)
            new_chat.destroy()

    tk.Button(new_chat, text="Start", command=start_chat).pack()

def connect():
    """Função de envio quando o botão 'Enviar' é clicado."""
    global User, Pass, IP, PORT
    User = nickname_entry.get()
    Pass = password_entry.get()
    IP = ip_entry.get()
    PORT = int(port_entry.get())
    send_to_server()
    
def create_user():
    """Function that calls send function when 'Create User is clicked'"""
    global User, Pass, IP, PORT
    User = nickname_entry.get()
    Pass = password_entry.get()
    IP = ip_entry.get()
    PORT = int(port_entry.get())
    send_create_user()

# Interface gráfica
root = tk.Tk()
root.title("Login")

# Campos para usuário e senha
tk.Label(root, text="Nickname").pack()
nickname_entry = tk.Entry(root)
nickname_entry.pack()

tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

# Campos para IP e Porta
tk.Label(root, text="IP").pack()
ip_entry = tk.Entry(root)
ip_entry.pack()

tk.Label(root, text="Port").pack()
port_entry = tk.Entry(root)
port_entry.pack()

# Botões para iniciar a comunicação e criar usuário
tk.Button(root, text="Connect", command=connect).pack()
tk.Button(root, text="Create User", command=create_user).pack()

root.mainloop()
