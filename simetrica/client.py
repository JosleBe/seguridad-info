"""
CLIENTE - Versión Simétrica Completa con Protocolo de Hashing Mejorado
- Cifrado: AES-256-CBC (confidencialidad)
- Hashing: HMAC-SHA256 (integridad) + SHA-256 (verificación de mensaje)
- Protocolo Dual: Hash del mensaje original + HMAC del mensaje cifrado
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
# COLORES PARA TERMINAL
# ===========================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

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

def create_message_hash(message):
    """Crea un hash SHA-256 del mensaje original (antes de cifrar)"""
    return hashlib.sha256(message.encode('utf-8')).digest()

def verify_message_hash(message, received_hash):
    """Verifica el hash SHA-256 del mensaje"""
    expected_hash = create_message_hash(message)
    return hmac.compare_digest(expected_hash, received_hash)

# ===========================
# ENVÍO Y RECEPCIÓN SEGURA
# ===========================
def send_secure_message(sock, message):
    try:
        # PROTOCOLO DE HASHING DUAL:
        # 1. Hash SHA-256 del mensaje original (32 bytes)
        message_hash = create_message_hash(message)
        
        # 2. Cifrado AES-256-CBC del mensaje
        encrypted_data = encrypt_message(message)
        
        # 3. HMAC-SHA256 del mensaje cifrado (32 bytes)
        message_hmac = create_hmac(encrypted_data)
        
        # Formato del paquete: [message_hash(32)][hmac(32)][encrypted_data(variable)]
        packet = message_hash + message_hmac + encrypted_data
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
        
        # PROTOCOLO DE HASHING DUAL - Extraer componentes:
        # [message_hash(32)][hmac(32)][encrypted_data(variable)]
        received_msg_hash = packet[:32]
        received_hmac = packet[32:64]
        encrypted_data = packet[64:]
        
        # VERIFICACIÓN 1: HMAC-SHA256 del mensaje cifrado (integridad en tránsito)
        if not verify_hmac(encrypted_data, received_hmac):
            error_msg = f"\n{Colors.RED}{Colors.BOLD}╔════════════════════════════════════════╗{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}║  ⚠️  ALERTA DE SEGURIDAD              ║{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}║  HMAC INVÁLIDO DETECTADO              ║{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}║  Mensaje corrupto en tránsito         ║{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}╚════════════════════════════════════════╝{Colors.END}"
            print(error_msg)
            return f"{Colors.RED}[MENSAJE CORRUPTO - HMAC INVÁLIDO]{Colors.END}"
        
        # Descifrar mensaje
        decrypted_message = decrypt_message(encrypted_data)
        if not decrypted_message:
            return None
        
        # VERIFICACIÓN 2: Hash SHA-256 del mensaje original (integridad del contenido)
        if not verify_message_hash(decrypted_message, received_msg_hash):
            expected_hash = hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()
            received_hash_hex = received_msg_hash.hex()
            
            error_msg = f"\n{Colors.RED}{Colors.BOLD}╔════════════════════════════════════════╗{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}║  🚨 CONTENIDO ALTERADO DETECTADO      ║{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}║  Hash SHA-256 no coincide             ║{Colors.END}"
            error_msg += f"\n{Colors.RED}{Colors.BOLD}╚════════════════════════════════════════╝{Colors.END}"
            error_msg += f"\n{Colors.YELLOW}Hash recibido:  {received_hash_hex}{Colors.END}"
            error_msg += f"\n{Colors.YELLOW}Hash esperado:  {expected_hash}{Colors.END}"
            error_msg += f"\n{Colors.RED}Mensaje original alterado - NO CONFIAR{Colors.END}\n"
            print(error_msg)
            return f"{Colors.RED}[CONTENIDO ALTERADO - HASH INVÁLIDO]{Colors.END}"
        
        # ✅ Mensaje verificado correctamente
        return decrypted_message
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
                # Si el mensaje contiene alertas de seguridad, ya viene con color
                if "[MENSAJE CORRUPTO" in message or "[CONTENIDO ALTERADO" in message:
                    print(f"\n{message}")
                else:
                    print(f"\n{Colors.CYAN}{message}{Colors.END}")
            else:
                break
        except Exception as e:
            print(f"{Colors.RED}[!] Error al recibir mensaje: {e}{Colors.END}")
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
        print("[🔨] Hashing Dual: SHA-256 (Mensaje) + HMAC-SHA256 (Integridad)")
        print("[✓] Protocolo: Hash del mensaje original + HMAC del cifrado")
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
            print("[✓] Protocolo de hashing dual: SHA-256 + HMAC-SHA256")
            print("[✓] Doble verificación de integridad en cada mensaje")
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
