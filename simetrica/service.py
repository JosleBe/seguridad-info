"""
SERVIDOR - Versión Simétrica Completa con Protocolo de Hashing Mejorado
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
# AES-256 (32 bytes exactos)
SYMMETRIC_KEY = hashlib.sha256(b"mi_clave_super_segura_para_aes").digest()
# HMAC-SHA256 (32 bytes exactos)
HMAC_KEY = hashlib.sha256(b"mi_clave_segura_para_hmac").digest()

# ===========================
# USUARIOS
# ===========================
usuarios_validos = {
    "admin": hashlib.sha256("clave123".encode()).hexdigest(),
    "usuario1": hashlib.sha256("clave123".encode()).hexdigest(),
    "usuario2": hashlib.sha256("clave123".encode()).hexdigest(),
    "usuario3": hashlib.sha256("clave123".encode()).hexdigest(),
    "usuario4": hashlib.sha256("clave123".encode()).hexdigest(),
    "usuario5": hashlib.sha256("clave123".encode()).hexdigest()
}

BANNED_FILE = "banned.txt"
clientes = set()
nombres = {}
sockets_por_matricula = {}
lock = threading.Lock()
banned = set()

# ===========================
# FUNCIONES CRIPTO
# ===========================
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
        
        # Enviar longitud primero
        sock.sendall(struct.pack(">I", len(packet_b64)) + packet_b64)
    except Exception as e:
        print(f"[!] Error al enviar mensaje: {e}")

def receive_secure_message(sock):
    try:
        # Leer longitud primero
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
            error_msg = f"{Colors.RED}{Colors.BOLD}[⚠️ HMAC INVÁLIDO] Mensaje corrupto en tránsito{Colors.END}"
            print(error_msg)
            return "[MENSAJE CORRUPTO]"
        
        # Descifrar mensaje
        decrypted_message = decrypt_message(encrypted_data)
        if not decrypted_message:
            return None
        
        # VERIFICACIÓN 2: Hash SHA-256 del mensaje original (integridad del contenido)
        if not verify_message_hash(decrypted_message, received_msg_hash):
            expected_hash = hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()
            received_hash_hex = received_msg_hash.hex()
            
            error_msg = f"{Colors.RED}{Colors.BOLD}[🚨 CONTENIDO ALTERADO]{Colors.END} "
            error_msg += f"Hash recibido: {Colors.YELLOW}{received_hash_hex}{Colors.END} | "
            error_msg += f"Esperado: {Colors.YELLOW}{expected_hash}{Colors.END}"
            print(error_msg)
            return "[CONTENIDO ALTERADO]"
        
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
# BAN Y BROADCAST
# ===========================
def load_bans():
    global banned
    if os.path.exists(BANNED_FILE):
        with open(BANNED_FILE, "r", encoding="utf-8") as f:
            banned = set(l.strip() for l in f.readlines() if l.strip())
    else:
        banned = set()

def save_bans():
    with open(BANNED_FILE, "w", encoding="utf-8") as f:
        for m in sorted(banned):
            f.write(m + "\n")

def broadcast(emisor_sock, texto):
    with lock:
        muertos = []
        for c in list(clientes):
            if c is not emisor_sock:
                try:
                    send_secure_message(c, texto)
                except:
                    muertos.append(c)
        for m in muertos:
            clientes.discard(m)
            nombre = nombres.pop(m, None)
            if nombre:
                sockets_por_matricula.pop(nombre, None)

def disconnect_matricula(matricula, reason=None):
    with lock:
        sock = sockets_por_matricula.get(matricula)
        if not sock:
            return False
        try:
            if reason:
                send_secure_message(sock, f"SISTEMA: Has sido desconectado: {reason}")
        except:
            pass
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except:
            pass
        clientes.discard(sock)
        nombres.pop(sock, None)
        sockets_por_matricula.pop(matricula, None)
    broadcast(None, f"SISTEMA: {matricula} ha sido desconectado ({reason if reason else 'kick'})")
    return True

def ban_matricula(matricula):
    with lock:
        banned.add(matricula)
        save_bans()
    disconnect_matricula(matricula, reason="baneado permanentemente")

def unban_matricula(matricula):
    with lock:
        if matricula in banned:
            banned.discard(matricula)
            save_bans()
            return True
    return False

# ===========================
# ADMIN
# ===========================
def handle_admin_command(matricula, message):
    parts = message.strip().split()
    if not parts:
        return False, "Comando vacío."
    cmd = parts[0].lower()
    if cmd == "/ban" and len(parts) == 2:
        target = parts[1].strip()
        if target == "admin":
            return False, "No puedes banear al admin."
        ban_matricula(target)
        return True, f"{target} baneado."
    if cmd == "/unban" and len(parts) == 2:
        target = parts[1].strip()
        ok = unban_matricula(target)
        return True, f"{target} desbaneado." if ok else f"{target} no estaba baneado."
    if cmd == "/kick" and len(parts) == 2:
        target = parts[1].strip()
        ok = disconnect_matricula(target, reason="expulsado por admin")
        return True, f"{target} expulsado." if ok else f"{target} no estaba conectado."
    if cmd == "/listbans":
        with lock:
            return True, "Baneados: " + ", ".join(sorted(banned)) if banned else "No hay baneados."
    return False, "Comando no reconocido. Usa /ban, /unban, /kick, /listbans."

# ===========================
# CLIENTE
# ===========================
def handle_client(client_socket, addr):
    try:
        matricula = client_socket.recv(1024).decode('utf-8').strip()
        client_socket.send("Solicita contraseña:".encode('utf-8'))
        hashed_password = client_socket.recv(1024).decode('utf-8').strip()

        if matricula in banned:
            try:
                client_socket.send("banned".encode('utf-8'))
            except:
                pass
            client_socket.close()
            print(f"[{addr}] Matricula baneada: {matricula}")
            return

        if usuarios_validos.get(matricula) == hashed_password:
            client_socket.send("aceptado".encode('utf-8'))
            print(f"[{addr}] Autenticado: {matricula} [🔐AES+HMAC]")

            with lock:
                clientes.add(client_socket)
                nombres[client_socket] = matricula
                sockets_por_matricula[matricula] = client_socket

            broadcast(client_socket, f"SISTEMA: {matricula} se unió al chat")

            while True:
                mensaje = receive_secure_message(client_socket)
                if not mensaje:
                    break

                if matricula == "admin" and mensaje.startswith("/"):
                    ok, resp = handle_admin_command(matricula, mensaje)
                    send_secure_message(client_socket, f"SISTEMA: {resp}")
                    continue

                print(f"[{matricula}] > {mensaje}")
                broadcast(client_socket, f"{matricula}: {mensaje}")

        else:
            client_socket.send("no aceptado".encode('utf-8'))
            print(f"[{addr}] Autenticación fallida: {matricula}")
    except Exception as e:
        print(f"Error con cliente {addr}: {e}")
    finally:
        nombre = None
        with lock:
            clientes.discard(client_socket)
            nombre = nombres.pop(client_socket, None)
            if nombre:
                sockets_por_matricula.pop(nombre, None)
        try:
            client_socket.close()
        except:
            pass
        if nombre:
            broadcast(None, f"SISTEMA: {nombre} salió del chat")
        print(f"[{addr}] Conexión cerrada")

# ===========================
# CONSOLA
# ===========================
def console_thread():
    help_text = ("Comandos de consola:\n"
                 "  ban <matricula>, unban <matricula>, kick <matricula>\n"
                 "  listbans, listusers, help, exit\n")
    print(help_text)
    while True:
        try:
            cmd = input("console> ").strip()
        except EOFError:
            break
        if not cmd:
            continue
        parts = cmd.split()
        if parts[0].lower() == "ban" and len(parts) == 2:
            m = parts[1].strip()
            if m == "admin":
                print("No puedes banear al admin.")
                continue
            ban_matricula(m)
            print(f"{m} baneado.")
        elif parts[0].lower() == "unban" and len(parts) == 2:
            m = parts[1].strip()
            ok = unban_matricula(m)
            print(f"{m} desbaneado." if ok else f"{m} no estaba baneado.")
        elif parts[0].lower() == "kick" and len(parts) == 2:
            m = parts[1].strip()
            ok = disconnect_matricula(m, reason="expulsado por consola")
            print(f"{m} expulsado." if ok else f"{m} no estaba conectado.")
        elif parts[0].lower() == "listbans":
            with lock:
                print("Baneados:", ", ".join(sorted(banned)) if banned else "Ninguno")
        elif parts[0].lower() == "listusers":
            with lock:
                print("Conectados:", ", ".join(sorted(sockets_por_matricula.keys())))
        elif parts[0].lower() == "help":
            print(help_text)
        elif parts[0].lower() == "exit":
            print("Cerrando servidor...")
            os._exit(0)
        else:
            print("Comando no reconocido. Escribe 'help'.")

# ===========================
# SERVIDOR
# ===========================
def start_server():
    load_bans()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)

    print("[*] Servidor escuchando en puerto 12345...")
    print("[🔐] Cifrado: AES-256-CBC (Simétrico)")
    print("[🔨] Hashing Dual: SHA-256 (Mensaje) + HMAC-SHA256 (Integridad)")
    print("[✓] Protocolo: Hash del mensaje original + HMAC del cifrado")
    print("[🔑] Contraseñas: SHA-256 (Hashing)")
    print(f"[i] Baneados: {len(banned)}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="../cert.pem", keyfile="../key.pem")

    threading.Thread(target=console_thread, daemon=True).start()
    while True:
        client, addr = server_socket.accept()
        try:
            secure_client = context.wrap_socket(client, server_side=True)
        except Exception as e:
            print(f"[!] Error SSL: {e}")
            client.close()
            continue
        print(f"[+] Cliente conectado desde {addr}")
        threading.Thread(target=handle_client, args=(secure_client, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
