================================================================================
                    MYCHAT - SISTEMA DE CHAT SEGURO
                    README Y DOCUMENTACIÓN DE VERSIONES
================================================================================

PROYECTO: MyChat - Sistema de Chat con Cifrado Simétrico y Asimétrico
FECHA DE INICIO: 19 de Octubre de 2025
CLIENTE: [Nombre del Cliente]
DESARROLLADOR: [Tu Nombre]

================================================================================
                            DESCRIPCIÓN DEL PROYECTO
================================================================================

MyChat es un sistema de mensajería seguro que implementa dos versiones de 
cifrado para garantizar la confidencialidad, integridad y autenticidad de 
las comunicaciones:

1. VERSIÓN SIMÉTRICA (simetrica/)
   - Cifrado: AES-256-CBC para confidencialidad de mensajes
   - Hashing: HMAC-SHA256 para verificación de integridad
   - Contraseñas: SHA-256 para almacenamiento seguro
   - Transporte: TLS/SSL

2. VERSIÓN ASIMÉTRICA (asimetrica/)
   - Cifrado: RSA-2048 + AES-256 (híbrido) para confidencialidad
   - Hashing: Firmas Digitales RSA-SHA256 para autenticidad e integridad
   - Contraseñas: SHA-256 para almacenamiento seguro
   - Transporte: TLS/SSL

================================================================================
                        ANÁLISIS DE CUMPLIMIENTO DE REQUISITOS
================================================================================

✓ REQUISITO 1: Cifrado SHA256 para seguridad de mensajes
  ESTADO: CUMPLIDO
  IMPLEMENTACIÓN:
  - Versión Simétrica: Utiliza HMAC-SHA256 para garantizar la integridad
    de cada mensaje. Cada mensaje cifrado con AES-256 lleva su HMAC para
    verificar que no ha sido modificado.
  - Versión Asimétrica: Utiliza Firmas Digitales RSA-SHA256 para garantizar
    tanto la autenticidad como la integridad. Cada mensaje está firmado
    digitalmente usando SHA-256 como algoritmo de hash.
  - Contraseñas: Todas las contraseñas se hashean con SHA-256 antes de ser
    transmitidas o almacenadas.

✓ REQUISITO 2: Versionado y documentación de cambios
  ESTADO: CUMPLIDO
  IMPLEMENTACIÓN:
  - Este archivo (readme.txt) documenta todas las versiones y cambios
  - Se mantiene un documento de control de cambios separado (control_cambios.txt)
  - Cada versión está claramente identificada y documentada

✓ REQUISITO 3: Documentación de MD5 de archivos .py
  ESTADO: CUMPLIDO
  IMPLEMENTACIÓN:
  - Cada versión registra los hashes MD5 de todos los archivos .py
  - Los MD5 se documentan tanto en este readme como en el control de cambios
  - Permite verificar la integridad de los archivos en cada versión

================================================================================
                        HISTORIAL DE VERSIONES
================================================================================

--------------------------------------------------------------------------------
VERSIÓN 1.0.0 - VERSIÓN INICIAL
Fecha: 19 de Octubre de 2025
--------------------------------------------------------------------------------

DESCRIPCIÓN:
Primera versión funcional del sistema MyChat con implementaciones completas
de cifrado simétrico y asimétrico. Incluye todas las características de
seguridad especificadas en los requisitos.

CARACTERÍSTICAS IMPLEMENTADAS:
- Sistema de autenticación con contraseñas hasheadas (SHA-256)
- Cifrado de mensajes con AES-256-CBC (simétrica) y RSA-2048+AES-256 (asimétrica)
- Verificación de integridad con HMAC-SHA256 (simétrica) y Firmas RSA-SHA256 (asimétrica)
- Sistema de usuarios con 6 cuentas predefinidas (admin + 5 usuarios)
- Comandos de administración: /ban, /unban, /kick, /listbans
- Sistema de baneos persistente
- Transporte seguro con TLS/SSL
- Interfaz de consola para administración del servidor
- Broadcast de mensajes a todos los usuarios conectados

ARCHIVOS Y HASHES MD5:
┌─────────────────────────────┬──────────────────────────────────┐
│ Archivo                     │ MD5                              │
├─────────────────────────────┼──────────────────────────────────┤
│ simetrica/service.py        │ 4AAB3B47E85B88C5F461E39AB63834A1 │
│ simetrica/client.py         │ 93F14E26C869857EA73961B2C1211E69 │
│ asimetrica/service.py       │ 867CE08AB0C1023CBC04A10852410730 │
│ asimetrica/client.py        │ CAC8C6592EA48BDDCD9D9AB521FE0D3F │
└─────────────────────────────┴──────────────────────────────────┘

USUARIOS PREDEFINIDOS:
- admin (contraseña: clave123) - Usuario con privilegios administrativos
- usuario1 (contraseña: clave123)
- usuario2 (contraseña: clave123)
- usuario3 (contraseña: clave123)
- usuario4 (contraseña: clave123)
- usuario5 (contraseña: clave123)

PUERTOS:
- Versión Simétrica: Puerto 12345
- Versión Asimétrica: Puerto 54321

CERTIFICADOS SSL/TLS:
- cert.pem y key.pem en el directorio raíz

ARCHIVOS DE CONFIGURACIÓN:
- banned.txt: Lista de usuarios baneados (se crea automáticamente)

================================================================================
                        INSTRUCCIONES DE USO
================================================================================

VERSIÓN SIMÉTRICA:
------------------
1. Iniciar el servidor:
   python simetrica/service.py

2. Iniciar cliente(s):
   python simetrica/client.py
   - Ingresar IP del servidor
   - Ingresar matrícula (admin, usuario1, usuario2, etc.)
   - Ingresar contraseña (clave123 para todos)

VERSIÓN ASIMÉTRICA:
-------------------
1. Iniciar el servidor:
   python asimetrica/service.py

2. Iniciar cliente(s):
   python asimetrica/client.py
   - Ingresar IP del servidor
   - Ingresar matrícula (admin, usuario1, usuario2, etc.)
   - Ingresar contraseña (clave123 para todos)

COMANDOS DE ADMINISTRADOR (solo para usuario "admin"):
-------------------------------------------------------
- /ban <matricula>      - Banea permanentemente a un usuario
- /unban <matricula>    - Quita el baneo a un usuario
- /kick <matricula>     - Expulsa temporalmente a un usuario
- /listbans             - Lista todos los usuarios baneados

COMANDOS DE CONSOLA DEL SERVIDOR:
----------------------------------
- ban <matricula>       - Banea permanentemente a un usuario
- unban <matricula>     - Quita el baneo a un usuario
- kick <matricula>      - Expulsa temporalmente a un usuario
- listbans              - Lista todos los usuarios baneados
- listusers             - Lista todos los usuarios conectados
- help                  - Muestra la ayuda
- exit                  - Cierra el servidor

COMANDOS DEL CLIENTE:
---------------------
- salir                 - Desconecta del chat

================================================================================
                        DETALLES TÉCNICOS DE SEGURIDAD
================================================================================

VERSIÓN SIMÉTRICA:
------------------
1. Cifrado de Mensajes:
   - Algoritmo: AES-256-CBC
   - Clave: Derivada de SHA-256 de una frase secreta
   - IV: Generado aleatoriamente para cada mensaje (16 bytes)
   - Padding: PKCS7

2. Integridad:
   - Algoritmo: HMAC-SHA256
   - Clave HMAC: Derivada de SHA-256 de una frase secreta separada
   - Verificación: Antes de descifrar cada mensaje

3. Formato de Paquete:
   [HMAC(32 bytes)][IV(16 bytes)][Datos Cifrados(variable)]
   Todo codificado en Base64 para transmisión

VERSIÓN ASIMÉTRICA:
-------------------
1. Intercambio de Claves:
   - Generación de pares RSA-2048 en servidor y cliente
   - Intercambio de claves públicas
   - Cliente genera clave de sesión AES-256 aleatoria
   - Clave de sesión cifrada con RSA y enviada al servidor

2. Cifrado de Mensajes:
   - Algoritmo: AES-256-CBC con clave de sesión
   - IV: Generado aleatoriamente para cada mensaje (16 bytes)
   - Padding: PKCS7

3. Autenticidad e Integridad:
   - Firmas Digitales RSA con PSS padding
   - Algoritmo de hash: SHA-256
   - Cada mensaje cifrado está firmado digitalmente
   - Verificación de firma antes de descifrar

4. Formato de Paquete:
   [Firma Digital(256 bytes)][IV(16 bytes)][Datos Cifrados(variable)]
   Todo codificado en Base64 para transmisión

CONTRASEÑAS:
------------
- Algoritmo: SHA-256
- Las contraseñas se hashean en el cliente antes de enviarlas
- El servidor almacena y compara hashes, nunca contraseñas en texto plano
- Hash almacenado: SHA-256(contraseña)

TRANSPORTE:
-----------
- Protocolo: TLS/SSL sobre TCP
- Certificados: cert.pem y key.pem
- El cliente no verifica certificados (desarrollo)
- Puertos: 12345 (simétrica), 54321 (asimétrica)

================================================================================
                        DEPENDENCIAS
================================================================================

Python 3.7 o superior

Bibliotecas requeridas:
- cryptography (pip install cryptography)
  - Proporciona primitivas criptográficas (AES, RSA, HMAC, etc.)
- socket (biblioteca estándar)
- ssl (biblioteca estándar)
- threading (biblioteca estándar)
- hashlib (biblioteca estándar)
- base64 (biblioteca estándar)
- struct (biblioteca estándar)
- os (biblioteca estándar)

Instalación de dependencias:
pip install cryptography

================================================================================
                        NOTAS DE SEGURIDAD
================================================================================

IMPORTANTE - SOLO PARA DESARROLLO:
-----------------------------------
Este sistema está diseñado para fines educativos y de demostración. Para un
entorno de producción, se recomienda:

1. Cambiar las claves simétricas hardcodeadas por un sistema de gestión de
   claves adecuado (KMS)

2. Implementar un sistema de gestión de certificados SSL/TLS apropiado con
   certificados válidos firmados por una CA

3. Usar contraseñas más robustas y un sistema de autenticación más seguro
   (como OAuth2, JWT, etc.)

4. Implementar rate limiting y protección contra ataques de fuerza bruta

5. Agregar logging y auditoría de eventos de seguridad

6. Implementar manejo de sesiones con timeouts

7. Validar y sanitizar todas las entradas de usuario

8. Implementar Perfect Forward Secrecy (PFS) en la versión asimétrica

9. Considerar el uso de bibliotecas de alto nivel como NaCl/libsodium

10. Realizar auditorías de seguridad y pruebas de penetración

================================================================================
                        PRÓXIMAS VERSIONES PLANIFICADAS
================================================================================

VERSIÓN 1.1.0 (Planificada):
- Mejoras en el sistema de logging
- Persistencia de mensajes
- Sistema de salas/canales
- Mensajes privados entre usuarios

VERSIÓN 1.2.0 (Planificada):
- Interfaz gráfica de usuario (GUI)
- Transferencia de archivos cifrados
- Notificaciones

VERSIÓN 2.0.0 (Planificada):
- Base de datos para usuarios y mensajes
- Sistema de autenticación más robusto
- API REST para integración con otros sistemas

================================================================================
                        CONTACTO Y SOPORTE
================================================================================

Para preguntas, sugerencias o reporte de bugs:
- Email: [tu-email@ejemplo.com]
- Proyecto: MyChat
- Versión Actual: 1.0.0

================================================================================
                        LICENCIA
================================================================================

[Especificar la licencia según corresponda]

================================================================================
FIN DEL DOCUMENTO
================================================================================
