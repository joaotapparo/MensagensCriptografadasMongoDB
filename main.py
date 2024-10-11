import os
from pymongo import MongoClient
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes 

client = MongoClient("mongodb://localhost:27017/")
db = client["chat_db"]
messages_collection = db["messages"]

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), 
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def insert_message(sender: str, receiver: str, message: str, password: str):
    salt = os.urandom(16) 
    key = derive_key(password, salt)
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    messages_collection.insert_one({
        "sender": sender,
        "receiver": receiver,
        "message": encrypted_message,
        "salt": salt
    })
    print("Mensagem criptografada e salva com sucesso!")

def fetch_messages(receiver: str, password: str):
    messages = messages_collection.find({"receiver": receiver})
    for msg in messages:
        salt = msg["salt"]  
        key = derive_key(password, salt) 
        cipher = Fernet(key)
        try:
            decrypted_message = cipher.decrypt(msg["message"]).decode()
            print(f"De {msg['sender']} para {msg['receiver']}: {decrypted_message}")
        except Exception as e:
            print(f"Falha ao descriptografar a mensagem: {e}")

def menu():
    while True:
        print("\n1. Enviar mensagem")
        print("2. Ler mensagens")
        print("3. Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            sender = input("Digite o remetente: ")
            receiver = input("Digite o destinatário: ")
            message = input("Digite a mensagem: ")
            password = input("Digite a senha de criptografia (não será armazenada): ")
            insert_message(sender, receiver, message, password)
        elif choice == '2':
            receiver = input("Digite o destinatário: ")
            password = input("Digite a senha de descriptografia: ")
            fetch_messages(receiver, password)
        elif choice == '3':
            print("Saindo...")
            break
        else:
            print("Opção inválida, tente novamente.")

if __name__ == "__main__":
    menu()
