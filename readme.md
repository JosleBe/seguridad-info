# 🛡️ MyChat - Sistema de Chat Seguro

**README y Documentación de Versiones**

---

## 📘 Información General

| Campo | Descripción |
|-------|--------------|
| **Proyecto** | MyChat - Sistema de Chat con Cifrado Simétrico y Asimétrico |
| **Fecha de Inicio** | 19 de Octubre de 2025 |
| **Cliente** | [Nombre del Cliente] |
| **Desarrollador** | [Tu Nombre] |

---

## 🧩 Descripción del Proyecto

**MyChat** es un sistema de mensajería segura que implementa dos versiones de cifrado para garantizar la **confidencialidad, integridad y autenticidad** de las comunicaciones.

### 🔹 Versión Simétrica (`simetrica/`)
- **Cifrado:** AES-256-CBC  
- **Hashing:** HMAC-SHA256 (integridad de mensajes)  
- **Contraseñas:** SHA-256  
- **Transporte:** TLS/SSL  

### 🔹 Versión Asimétrica (`asimetrica/`)
- **Cifrado híbrido:** RSA-2048 + AES-256  
- **Firmas digitales:** RSA-SHA256  
- **Contraseñas:** SHA-256  
- **Transporte:** TLS/SSL  

---

## ✅ Análisis de Cumplimiento de Requisitos

### **Requisito 1:** Cifrado SHA256 para seguridad de mensajes  
**Estado:** ✅ Cumplido  
**Implementación:**
- **Simétrica:** HMAC-SHA256 para verificar integridad.  
- **Asimétrica:** Firmas digitales RSA-SHA256 para autenticidad e integridad.  
- **Contraseñas:** Hasheadas con SHA-256 antes de enviarse o almacenarse.  

---

### **Requisito 2:** Versionado y documentación de cambios  
**Estado:** ✅ Cumplido  
**Implementación:**
- Este archivo (`README.md`) documenta todas las versiones.  
- Se mantiene un documento complementario (`control_cambios.txt`).  
- Cada versión se identifica claramente con fecha y número.  

---

### **Requisito 3:** Documentación de MD5 de archivos `.py`  
**Estado:** ✅ Cumplido  
**Implementación:**
- Cada versión registra los hashes MD5 de los archivos principales.  
- Los valores se documentan aquí y en el control de cambios.  
- Permite verificar la integridad del código fuente.  

---

## 🧾 Historial de Versiones

### 🟢 **Versión 1.0.0 — Versión Inicial**
**Fecha:** 19 de Octubre de 2025  

**Descripción:**  
Primera versión funcional de MyChat con cifrado simétrico y asimétrico, cumpliendo los requisitos de seguridad.

**Características Implementadas:**
- Autenticación con contraseñas hasheadas (SHA-256)  
- Cifrado de mensajes AES-256-CBC (simétrica) y RSA-2048 + AES-256 (asimétrica)  
- Verificación de integridad con HMAC-SHA256 y firmas RSA-SHA256  
- Sistema de usuarios con 6 cuentas predefinidas  
- Comandos de administración (`/ban`, `/unban`, `/kick`, `/listbans`)  
- Baneos persistentes  
- Transporte seguro con TLS/SSL  
- Interfaz de consola administrativa  
- Broadcast de mensajes  

---

### 📂 Archivos y Hashes MD5

| Archivo | MD5 |
|----------|-----|
| `simetrica/service.py` | `4AAB3B47E85B88C5F461E39AB63834A1` |
| `simetrica/client.py`  | `93F14E26C869857EA73961B2C1211E69` |
| `asimetrica/service.py` | `867CE08AB0C1023CBC04A10852410730` |
| `asimetrica/client.py` | `CAC8C6592EA48BDDCD9D9AB521FE0D3F` |

---

### 👥 Usuarios Predefinidos

| Usuario | Contraseña | Rol |
|----------|-------------|-----|
| admin | clave123 | Administrador |
| usuario1 | clave123 | Usuario |
| usuario2 | clave123 | Usuario |
| usuario3 | clave123 | Usuario |
| usuario4 | clave123 | Usuario |
| usuario5 | clave123 | Usuario |

---

### 🔌 Puertos

| Versión | Puerto |
|----------|--------|
| Simétrica | 12345 |
| Asimétrica | 54321 |

---

### 🔒 Certificados SSL/TLS
- Archivos: `cert.pem` y `key.pem` (directorio raíz)

### ⚙️ Archivos de Configuración
- `banned.txt`: lista de usuarios baneados (generado automáticamente)

---

## 🧭 Instrucciones de Uso

### 🧱 Versión Simétrica
```bash
# Servidor
python simetrica/service.py

# Cliente
python simetrica/client.py