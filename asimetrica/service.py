"""
SERVIDOR - Versión Asimétrica Completa
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

# Contraseñas hasheadas con SHA-256
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
session_keys = {}
client_public_keys = {}
lock = threading.Lock()
banned = set()

server_private_key = None
server_public_key = None

def generate_server_keys():
    """Genera el par de claves RSA del """
    global server_private_key, server_public_key
    print("[🔑] Generando claves RSA del servidor...")
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    server_public_key = server_private_key.public_key()
    print("[✓] Claves RSA generadas")

def sign_message(message):
    """Firma digital con RSA (HASHING ASIMÉTRICO)"""
    signature = server_private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, pub_key):
    """Verifica firma digital"""
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

def decrypt_with_rsa(encrypted_message):
    """Descifra con la clave privada del servidor"""
    try:
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = server_private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    except:
        return None

def encrypt_with_aes(message, key):
    """Cifra con AES"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

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
    except:
        return None

def send_secure_message(sock, message, session_key):
    """Cifra con AES, firma y envía"""
    encrypted_data = encrypt_with_aes(message, session_key)
    signature = sign_message(encrypted_data)
    packet = signature + encrypted_data
    packet_b64 = base64.b64encode(packet).decode('utf-8')
    sock.send(packet_b64.encode('utf-8'))

def receive_secure_message(sock, session_key, client_pub_key):
    """Recibe, verifica firma y descifra"""
    try:
        packet_b64 = sock.recv(8192).decode('utf-8')
        if not packet_b64:
            return None
        packet = base64.b64decode(packet_b64.encode('utf-8'))
        signature = packet[:256]
        encrypted_data = packet[256:]
        if not verify_signature(encrypted_data, signature, client_pub_key):
            print("[!] Firma digital inválida")
            return None
        return decrypt_with_aes(encrypted_data, session_key)
    except:
        return None

def load_bans():
    """Carga la lista de baneados"""
    global banned
    if os.path.exists(BANNED_FILE):
        with open(BANNED_FILE, "r", encoding="utf-8") as f:
            banned = set(l.strip() for l in f.readlines() if l.strip())
    else:
        banned = set()

def save_bans():
    """Guarda la lista de baneados"""
    with open(BANNED_FILE, "w", encoding="utf-8") as f:
        for m in sorted(banned):
            f.write(m + "\n")

def broadcast(emisor_sock, texto):
    """Envía mensaje a todos excepto al emisor"""
    with lock:
        muertos = []
        for c in list(clientes):
            if c is not emisor_sock:
                try:
                    session_key = session_keys.get(c)
                    if session_key:
                        send_secure_message(c, texto, session_key)
                except Exception:
                    muertos.append(c)
        for m in muertos:
            clientes.discard(m)
            nombre = nombres.pop(m, None)
            if nombre:
                sockets_por_matricula.pop(nombre, None)
            session_keys.pop(m, None)
            client_public_keys.pop(m, None)

def disconnect_matricula(matricula, reason=None):
    """Desconecta un usuario por matrícula"""
    with lock:
        sock = sockets_por_matricula.get(matricula)
        if not sock:
            return False
        try:
            if reason:
                session_key = session_keys.get(sock)
                if session_key:
                    send_secure_message(sock, f"SISTEMA: Has sido desconectado: {reason}", session_key)
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
        session_keys.pop(sock, None)
        client_public_keys.pop(sock, None)
    broadcast(None, f"SISTEMA: {matricula} ha sido desconectado ({reason if reason else 'kick'})")
    return True

def ban_matricula(matricula):
    """Banea y desconecta un usuario"""
    with lock:
        banned.add(matricula)
        save_bans()
    disconnect_matricula(matricula, reason="baneado permanentemente")

def unban_matricula(matricula):
    """Quita el baneo"""
    with lock:
        if matricula in banned:
            banned.discard(matricula)
            save_bans()
            return True
    return False

def handle_admin_command(matricula, message):
    """Procesa comandos de administrador"""
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

def handle_client(client_socket, addr):
    """Maneja la conexión de un cliente"""
    session_key = None
    client_public_key = None
    try:
        # PASO 1: Envía clave pública del servidor
        server_pub_pem = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        client_socket.send(server_pub_pem.encode('utf-8'))
        
        # PASO 2: Recibe clave pública del cliente
        client_pub_pem = client_socket.recv(4096).decode('utf-8')
        client_public_key = serialization.load_pem_public_key(
            client_pub_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # PASO 3: Recibe clave de sesión AES
        encrypted_session_key = client_socket.recv(4096).decode('utf-8')
        session_key_b64 = decrypt_with_rsa(encrypted_session_key)
        if not session_key_b64:
            print(f"[{addr}] Error al descifrar clave de sesión")
            client_socket.close()
            return
        
        session_key = base64.b64decode(session_key_b64.encode('utf-8'))
        session_keys[client_socket] = session_key
        client_public_keys[client_socket] = client_public_key
        print(f"[{addr}] Intercambio de claves completado")
        
        # PASO 4: Autenticación
        matricula = receive_secure_message(client_socket, session_key, client_public_key)
        if not matricula:
            client_socket.close()
            return
        matricula = matricula.strip()
        
        send_secure_message(client_socket, "Solicita contraseña:", session_key)
        
        hashed_password = receive_secure_message(client_socket, session_key, client_public_key)
        if not hashed_password:
            client_socket.close()
            return
        hashed_password = hashed_password.strip()

        # Verifica si está baneado
        if matricula in banned:
            try:
                send_secure_message(client_socket, "banned", session_key)
            except:
                pass
            client_socket.close()
            print(f"[{addr}] Matricula baneada: {matricula}")
            return

        # Verifica credenciales
        if usuarios_validos.get(matricula) == hashed_password:
            send_secure_message(client_socket, "aceptado", session_key)
            print(f"[{addr}] Autenticado: {matricula} [🔐RSA+AES+Firmas]")

            with lock:
                clientes.add(client_socket)
                nombres[client_socket] = matricula
                sockets_por_matricula[matricula] = client_socket

            broadcast(client_socket, f"SISTEMA: {matricula} se unió al chat")

            # Recibe mensajes
            while True:
                try:
                    mensaje = receive_secure_message(client_socket, session_key, client_public_key)
                    if not mensaje:
                        break

                    # Comandos admin
                    if matricula == "admin" and mensaje.startswith("/"):
                        ok, resp = handle_admin_command(matricula, mensaje)
                        send_secure_message(client_socket, f"SISTEMA: {resp}", session_key)
                        continue

                    print(f"[{matricula}] > {mensaje}")
                    broadcast(client_socket, f"{matricula}: {mensaje}")
                except Exception as e:
                    print(f"Error con {matricula}: {e}")
                    break
        else:
            send_secure_message(client_socket, "no aceptado", session_key)
            print(f"[{addr}] Autenticación fallida: {matricula}")
    except Exception as e:
        print(f"Error con cliente {addr}: {e}")
    finally:
        # Limpieza
        nombre = None
        with lock:
            clientes.discard(client_socket)
            nombre = nombres.pop(client_socket, None)
            if nombre:
                sockets_por_matricula.pop(nombre, None)
            session_keys.pop(client_socket, None)
            client_public_keys.pop(client_socket, None)
        try:
            client_socket.close()
        except:
            pass
        if nombre:
            broadcast(None, f"SISTEMA: {nombre} salió del chat")
        print(f"[{addr}] Conexión cerrada")

def console_thread():
    """Hilo de comandos de consola"""
    help_text = ("Comandos: ban, unban, kick <matricula> | listbans, listusers, help, exit\n")
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
            print("Comando no reconocido.")

def start_server():
    """Inicia el servidor"""
    generate_server_keys()
    load_bans()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 54321))
    server_socket.listen(5)
    print("[*] Servidor escuchando en puerto 54321...")
    print("[🔐] Cifrado: RSA-2048 + AES-256 (Híbrido)")
    print("[🔨] Hashing: Firmas Digitales RSA-SHA256")
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