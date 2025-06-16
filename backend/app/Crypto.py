from cryptography.fernet import Fernet
import os

# Charge la clé depuis l'environnement
SECRET_KEY = os.getenv("FERNET_SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("FERNET_SECRET_KEY n'est pas défini dans .env")

fernet = Fernet(SECRET_KEY)

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data: str) -> str:
    return fernet.decrypt(data.encode()).decode()
