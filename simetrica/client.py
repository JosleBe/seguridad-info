"""
CLIENTE - Versión Simétrica Completa
- Cifrado: AES-256-CBC (confidencialidad)
- Hashing: HMAC-SHA256 (integridad)
- Contraseñas: SHA-256 (hashing)
"""

import socket
import threading
import ssl
import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import struct

# ===========================
# CONFIGURACIÓN DE CLAVES
# ===========================
SYMMETRIC_KEY = hashlib.sha256(b"mi_clave_super_segura_para_aes").digest()
HMAC_KEY = hashlib.sha256(b"mi_clave_segura_para_hmac").digest()

# ===========================
# CRIPTO
# ===========================
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def encrypt_message(message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def decrypt_message(encrypted_data):
    try:
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode('utf-8')
    except:
        return None

def create_hmac(data):
    return hmac.new(HMAC_KEY, data, hashlib.sha256).digest()

def verify_hmac(data, received_hmac):
    return hmac.compare_digest(create_hmac(data), received_hmac)

# ===========================
# ENVÍO Y RECEPCIÓN SEGURA
# ===========================
def send_secure_message(sock, message):
    try:
        encrypted_data = encrypt_message(message)
        message_hmac = create_hmac(encrypted_data)
        packet = message_hmac + encrypted_data
        packet_b64 = base64.b64encode(packet)
        sock.sendall(struct.pack(">I", len(packet_b64)) + packet_b64)
    except Exception as e:
        print(f"[!] Error al enviar mensaje: {e}")

def receive_secure_message(sock):
    try:
        raw_len = recvall(sock, 4)
        if not raw_len:
            return None
        msg_len = struct.unpack(">I", raw_len)[0]
        packet_b64 = recvall(sock, msg_len)
        if not packet_b64:
            return None
        packet = base64.b64decode(packet_b64)
        received_hmac = packet[:32]
        encrypted_data = packet[32:]
        if not verify_hmac(encrypted_data, received_hmac):
            print("[!] HMAC inválido detectado")
            return "[MENSAJE CORRUPTO]"
        return decrypt_message(encrypted_data)
    except Exception as e:
        return None

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# ===========================
# RECEPCIÓN Y ENVÍO DE MENSAJES
# ===========================
def receive_messages(client_socket):
    while True:
        try:
            message = receive_secure_message(client_socket)
            if message:
                print(f"\n{message}")
            else:
                break
        except Exception as e:
            print(f"[!] Error al recibir mensaje: {e}")
            break

def send_messages(client_socket, mi_nombre):
    while True:
        try:
            message = input("Tu mensaje: ")
            if message.lower() == "salir":
                print("Desconectando...")
                try:
                    client_socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                client_socket.close()
                break
            send_secure_message(client_socket, message)
            print(f"Yo: {message}")
        except Exception as e:
            print(f"[!] Error al enviar mensaje: {e}")
            break

# ===========================
# CLIENTE
# ===========================
def start_client():
    server_ip = input("IP del servidor: ")
    server_port = 12345

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl._create_unverified_context()
    secure_socket = context.wrap_socket(raw_socket, server_hostname=server_ip)

    try:
        secure_socket.connect((server_ip, server_port))
        print("[+] Conectado al servidor de forma segura.")
        print("[🔐] Cifrado: AES-256-CBC (Simétrico)")
        print("[🔨] Hashing: HMAC-SHA256 (Integridad)")
        print("[🔑] Contraseñas: SHA-256 (Hashing)")

        matricula = input("Introduce tu matrícula: ").strip()
        secure_socket.send(matricula.encode('utf-8'))

        prompt = secure_socket.recv(1024).decode('utf-8')
        print(prompt)
        contrasena = input("Introduce tu contraseña: ").strip()

        hashed_password = hash_password(contrasena)
        secure_socket.send(hashed_password.encode('utf-8'))

        respuesta = secure_socket.recv(1024).decode('utf-8')
        if respuesta == "aceptado":
            print("[✓] Autenticación exitosa. Puedes comenzar a chatear.")
            print("[✓] Todos los mensajes están cifrados y autenticados con HMAC")
            threading.Thread(target=receive_messages, args=(secure_socket,), daemon=True).start()
            send_messages(secure_socket, matricula)
        elif respuesta == "banned":
            print("[✗] Tu cuenta está baneada. Conexión cerrada.")
            secure_socket.close()
        else:
            print("[✗] Matrícula o contraseña incorrecta. Conexión cerrada.")
            secure_socket.close()

    except Exception as e:
        print(f"[!] Error al conectar: {e}")
        try:
            secure_socket.close()
        except:
            pass

if __name__ == "__main__":
    start_client()
