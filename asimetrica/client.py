"""
CLIENTE - Versión Asimétrica Completa
- Cifrado: RSA-2048 + AES-256 (confidencialidad)
- Hashing: Firmas Digitales RSA (autenticidad e integridad)
- Contraseñas: SHA-256 (hashing)
"""
import socket
import threading
import ssl
import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# Claves del cliente
private_key = None
public_key = None
server_public_key = None
session_key = None

def generate_keys():
    """Genera par de claves RSA para el cliente"""
    global private_key, public_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

def hash_password(password):
    """Hashea la contraseña usando SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def sign_message(message):
    """Firma digitalmente un mensaje usando RSA (HASHING ASIMÉTRICO)"""
    signature = private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, pub_key):
    """Verifica la firma digital de un mensaje"""
    try:
        pub_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def encrypt_with_rsa(message, pub_key):
    """Cifra con RSA"""
    encrypted = pub_key.encrypt(
        message.encode('utf-8'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_with_rsa(encrypted_message):
    """Descifra con RSA"""
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    except Exception as e:
        return None

def encrypt_with_aes(message, key):
    """Cifra con AES"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + encrypted  # Retorna bytes

def decrypt_with_aes(encrypted_data, key):
    """Descifra con AES"""
    try:
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted.decode('utf-8')
    except Exception as e:
        return None

def send_secure_message(sock, message):
    """Cifra con AES, firma digitalmente y envía: [firma(256bytes)][datos_cifrados]"""
    encrypted_data = encrypt_with_aes(message, session_key)
    
    # Crea firma digital del mensaje cifrado
    signature = sign_message(encrypted_data)
    
    # Formato: Firma (256 bytes) + datos cifrados
    packet = signature + encrypted_data
    packet_b64 = base64.b64encode(packet).decode('utf-8')
    sock.send(packet_b64.encode('utf-8'))

def receive_secure_message(sock):
    """Recibe mensaje, verifica firma y descifra"""
    try:
        packet_b64 = sock.recv(8192).decode('utf-8')
        if not packet_b64:
            return None
        
        packet = base64.b64decode(packet_b64.encode('utf-8'))
        
        # Extrae firma (primeros 256 bytes para RSA-2048) y datos
        signature = packet[:256]
        encrypted_data = packet[256:]
        
        # Verifica firma digital (autenticidad e integridad)
        if not verify_signature(encrypted_data, signature, server_public_key):
            print("[!] ADVERTENCIA: Firma inválida - mensaje no auténtico")
            return "[MENSAJE NO AUTÉNTICO]"
        
        # Descifra
        return decrypt_with_aes(encrypted_data, session_key)
    except Exception as e:
        return None

def receive_messages(client_socket):
    while True:
        try:
            message = receive_secure_message(client_socket)
            if message:
                print(f"\n{message}")
            else:
                break
        except Exception as e:
            print(f"\n[!] Error al recibir mensaje: {e}")
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

def start_client():
    global server_public_key, session_key
    
    print("[🔑] Generando par de claves RSA...")
    generate_keys()
    
    server_ip = input("IP del servidor: ")
    server_port = 54321

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl._create_unverified_context()
    secure_socket = context.wrap_socket(raw_socket, server_hostname=server_ip)

    try:
        secure_socket.connect((server_ip, server_port))
        print("[+] Conectado al servidor de forma segura.")
        print("[🔐] Cifrado: RSA-2048 + AES-256 (Asimétrico + Simétrico)")
        print("[🔨] Hashing: Firmas Digitales RSA-SHA256 (Autenticidad)")
        print("[🔑] Contraseñas: SHA-256 (Hashing)")

        # PASO 1: Recibe clave pública del servidor
        server_pub_pem = secure_socket.recv(4096).decode('utf-8')
        server_public_key = serialization.load_pem_public_key(
            server_pub_pem.encode('utf-8'),
            backend=default_backend()
        )
        print("[✓] Clave pública del servidor recibida")

        # PASO 2: Envía clave pública del cliente
        client_pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        secure_socket.send(client_pub_pem.encode('utf-8'))
        print("[✓] Clave pública enviada al servidor")

        # PASO 3: Genera y envía clave de sesión AES
        session_key = os.urandom(32)
        encrypted_session_key = encrypt_with_rsa(
            base64.b64encode(session_key).decode('utf-8'),
            server_public_key
        )
        secure_socket.send(encrypted_session_key.encode('utf-8'))
        print("[✓] Clave de sesión AES generada y enviada")

        # PASO 4: Autenticación con contraseña hasheada
        matricula = input("Introduce tu matrícula: ").strip()
        send_secure_message(secure_socket, matricula)

        prompt = receive_secure_message(secure_socket)
        print(prompt)
        
        contrasena = input("Introduce tu contraseña: ").strip()
        hashed_password = hash_password(contrasena)
        send_secure_message(secure_socket, hashed_password)

        respuesta = receive_secure_message(secure_socket)
        
        if respuesta == "aceptado":
            print("[✓] Autenticación exitosa. Puedes comenzar a chatear.")
            print("[✓] Todos los mensajes tienen firma digital para verificar autenticidad")
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
        import traceback
        traceback.print_exc()
        try:
            secure_socket.close()
        except:
            pass

if __name__ == "__main__":
    start_client()
