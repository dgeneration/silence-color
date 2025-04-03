from ctypes import windll
import cv2
from mss import mss
import numpy as np
from keyboard import is_pressed
import serial.tools.list_ports
from serial import Serial, SerialException
from time import sleep
from configparser import ConfigParser
from os import _exit, path, getcwd, urandom
from colorama import Fore
from win32api import GetAsyncKeyState,GetLongPathName
from threading import Lock, Thread
from hwid import get_hwid
from requests import post
from requests import exceptions
from json import dumps
from datetime import datetime
from subprocess import CREATE_NO_WINDOW , run
import tkinter as tk
from tkinter import ttk, messagebox
import queue
from PIL import Image, ImageTk
import pystray
from pystray import MenuItem as item
import hashlib
from winreg import HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx, CloseKey
from uuid import getnode
from psutil import process_iter, cpu_count
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json

def get_resource_path(relative_path):
    base_paths = []

    if getattr(sys, '_MEIPASS', None):
        base_paths.append(sys._MEIPASS)

    base_paths.append(path.dirname(path.abspath(sys.argv[0])))
    base_paths.append(path.dirname(path.abspath(__file__)))
    base_paths.append(getcwd())
    
    for base in base_paths:
        resolved = path.join(base, relative_path)
        if path.exists(resolved):
            try:
                resolved = GetLongPathName(resolved)
            except ImportError:
                pass
            except Exception as e:
                print(f"Path conversion error: {str(e)}")
            return resolved
    return path.abspath(relative_path)

def load_icon(window, icon_name):
    icon_path = get_resource_path(icon_name)
    
    try:
        window.iconbitmap(icon_path)
    except tk.TclError:
        abs_path = path.abspath(icon_path)
        window.tk.call('wm', 'iconbitmap', window._w, f'@{abs_path}')

def get_file_hash():
    try:
        if getattr(sys, 'frozen', False):
            file_path = sys.executable
        else:
            file_path = __file__
            
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
        
    except Exception as e:
        return "ERROR"

def is_debugger_present():
    return windll.kernel32.IsDebuggerPresent() != 0

def check_debugger_processes():
    debuggers = ['ollydbg.exe', 'ida64.exe', 'idaq.exe', 
                'windbg.exe', 'x32dbg.exe', 'x64dbg.exe',
                'dbgview.exe', 'procmon.exe', 'wireshark.exe']
    try:
        for proc in process_iter(['name']):
            if proc.info['name'].lower() in debuggers:
                return True
        return False
    except Exception:
        return False

def check_vm_registry():
    try:
        key = OpenKey(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
        manufacturer = QueryValueEx(key, "SystemManufacturer")[0].lower()
        product = QueryValueEx(key, "SystemProductName")[0].lower()
        CloseKey(key)
        vm_indicators = ['vmware', 'virtual', 'qemu', 'xen', 'kvm', 'hyper-v']
        return any(indicator in manufacturer or indicator in product for indicator in vm_indicators)
    except Exception:
        return False

def check_vm_files():
    vm_files = [
        r"C:\Windows\System32\Drivers\Vmmouse.sys",
        r"C:\Windows\System32\Drivers\vm3dgl.dll",
        r"C:\Windows\System32\Drivers\vmdum.dll",
        r"C:\Windows\System32\Drivers\vm3dver.dll",
        r"C:\Windows\System32\Drivers\vmci.sys",
        r"C:\Windows\System32\vboxhook.dll"
    ]
    return any(path.exists(file) for file in vm_files)

def check_vm_mac():
    mac = getnode()
    mac_bytes = [mac >> i & 0xff for i in range(0,8*6,8)][::-1]
    mac_address = ':'.join(['{:02x}'.format(b) for b in mac_bytes])
    vm_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', 
                   '00:50:56', '08:00:27', '0a:00:27']
    return any(mac_address.startswith(prefix) for prefix in vm_prefixes)

def check_cpu_cores():
    return cpu_count(logical=False) < 2

def is_vm():
    return (check_vm_registry() or 
            check_vm_files() or 
            check_vm_mac() or 
            check_cpu_cores())

def perform_security_checks(queue):
    if is_debugger_present():
        send_discord_webhook("Debugger detected!",16734208)
        queue.put(("error", "Debugger detected!"))
        return False

    if check_debugger_processes():
        send_discord_webhook("Debugging tools detected!",16734208)
        queue.put(("error", "Debugging tools detected!"))
        return False

    if is_vm():
        send_discord_webhook("Virtual machine detected!",16734208)
        queue.put(("error", "Virtual machine detected!"))
        return False

    try:
        get_file_hash()
    except Exception as e:
        send_discord_webhook("Integrity check failed!",16734208)
        queue.put(("error", f"Integrity check failed: {str(e)}"))
        return False

    return True

def detect_arduino_port():
    try:
        ports = serial.tools.list_ports.comports()
        for port in ports:
            desc_lower = port.description.lower()
            if 'arduino' in desc_lower or 'usb serial device' in desc_lower:
                return port.device
        raise SerialException("No Arduino or USB Serial Device found")
    except Exception as e:
        raise SerialException(f"Port detection error: {str(e)}")

windll.kernel32.SetConsoleTitleW("Silence Ai")

default_config = """
[Settings]
# COM Port for Arduino (use 'auto' for auto detect)
com_port = auto

# Color for detection (options: yellow, yellow 2, purple, anti astra, red, custom)
color = purple

# Virtual Key Code (https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes) (use 'auto' for auto aim)
aim_key = auto
trigger_key = 0x05

# Enabled by default (True/False)
aim_assist = False
trigger_bot = False

[Aim]
# Field of View for the Aim Assist (in pixels)
aim_fov = 65

# Aim Offset ( head, neck, body, custom)
aim_offset = head

# Aim Speed settings (X and Y axis)
aim_speed_x = 0.6
aim_speed_y = 0.3

[Trigger]
# Field of View for the Trigger Bot (in pixels)
trigger_fov = 8

# Trigger Delay (in milliseconds)
trigger_delay = 0.2

[Custom]
# Define the color ranges for detection (HSV values)
custom_lower = 23, 78, 199
custom_upper = 32, 255, 254

# Define custom Offset
custom_offset_y = 3
custom_offset_x = 0
"""

global_config = {}
config_lock = Lock()
arduino_lock = Lock()
ENCRYPTION_KEY = base64.b64decode("ZDqZYXkGJOXuHWFTyPhct0kYzKvLlKbSXC8GbwM+9kw=")
version = '1.0.1'
app = 'silence-color'
session_token = None
auth_server = "https://auth-a6s.pages.dev/check"
auth_check = "https://auth-a6s.pages.dev/renew-session"
auth_headers = {
    "Content-Type": "application/json",
    "X-Encrypted": "true"
}

def encrypt_data(plaintext_data):
    try:
        iv = urandom(12)
        plaintext = json.dumps(plaintext_data).encode('utf-8')
        aesgcm = AESGCM(ENCRYPTION_KEY)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return {
            'data': ciphertext.hex(),
            'iv': iv.hex()
        }
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_response(encrypted_hex, iv_hex):
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        
        aesgcm = AESGCM(ENCRYPTION_KEY)
        decrypted_bytes = aesgcm.decrypt(iv_bytes, encrypted_bytes, None)
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        return {"error": f"Decryption failed: {str(e)}"}
    
def check():
    renew_data = {
        "hwid": get_hwid(),
        "version": version,
        "app": app,
        "sessionToken": session_token
    }
    while True:
        encrypted_renew = encrypt_data(renew_data)
        auth_response = post(auth_check, headers=auth_headers, data=dumps(encrypted_renew), timeout=10)
        response_data = auth_response.json()
        if 'data' not in response_data or 'iv' not in response_data:
            raise ValueError("Invalid encrypted response format")

        decrypted = decrypt_response(response_data['data'], response_data['iv'])
        if 'error' in decrypted:
            _exit(0)
        
        sleep(250)

def create_default_config():
    with open('config.ini', 'w') as f:
        f.write(default_config)
    messagebox.showinfo("Error", f"Config not found. Creating default config.ini.")

def load_config():
    config = ConfigParser()
    if not path.exists('config.ini'):
        create_default_config()
    config.read('config.ini')

    com_port_str = config['Settings']['com_port']
    arduino = None

    try:
        if com_port_str.strip().lower() == 'auto':
            com = detect_arduino_port()
        else:
            com = com_port_str
        arduino = Serial(com, 115200, timeout=1)
        
    except SerialException as e:
        messagebox.showerror("Initialization Error", f"Failed to initialize Arduino: {str(e)}")
        raise
    except Exception as e:
        messagebox.showerror("Unexpected error", f"{str(e)}")
        raise

    aim_fov = int(config['Aim']['aim_fov'])
    aim_speed_x = float(config['Aim']['aim_speed_x'])
    aim_speed_y = float(config['Aim']['aim_speed_y'])

    trigger_delay = float(config['Trigger']['trigger_delay'])
    trigger_fov = int(config['Trigger']['trigger_fov'])

    aim_key_str = config['Settings']['aim_key']
    if aim_key_str.strip().lower() == 'auto':
        aim_key = 'auto'
    else:
        aim_key = int(aim_key_str, 16)
    
    trigger_key = int(config['Settings']['trigger_key'], 16)

    aim_offset_str = config['Aim']['aim_offset']
    aim_offset_x = 0

    if aim_offset_str == 'head':
        aim_offset = 8
    elif aim_offset_str == 'neck':
        aim_offset = 6
    elif aim_offset_str == 'body':
        aim_offset = 2
    elif aim_offset_str == 'custom':
        aim_offset = int(config['Custom']['custom_offset_y'])
        aim_offset_x = int(config['Custom']['custom_offset_x'])
    else:
        aim_offset = 8

    color = config['Settings']['color']
    if color == 'yellow':
        lower = np.array([30, 125, 150])
        upper = np.array([30, 255, 255])
    elif color == 'yellow 2':
        lower = np.array([30, 170, 254])
        upper = np.array([30, 230, 255])
    elif color == 'purple':
        lower = np.array([144, 72, 150])
        upper = np.array([152, 255, 255])
    elif color == 'anti astra':
        lower = np.array([135, 95, 200])
        upper = np.array([155, 255, 255])
    elif color == 'red':
        lower = np.array([0, 170, 150])
        upper = np.array([5, 255, 255])
    elif color == 'custom':
        lower = np.array([int(x) for x in config['Custom']['custom_lower'].split(',')])
        upper = np.array([int(x) for x in config['Custom']['custom_upper'].split(',')])
    else:
        lower = np.array([144, 72, 150])
        upper = np.array([152, 255, 255])

    aim_assist = config.getboolean('Settings', 'aim_assist')
    trigger_bot = config.getboolean('Settings', 'trigger_bot')

    return arduino, aim_fov, aim_speed_x, aim_speed_y, lower, upper, aim_assist, trigger_bot, aim_offset, aim_offset_x, aim_key, trigger_key, trigger_delay, trigger_fov,com

def initialize_global_config():
    try:
        new_arduino, aim_fov, aim_speed_x, aim_speed_y, lower, upper, aim_assist, trigger_bot, aim_offset, aim_offset_x, aim_key, trigger_key, trigger_delay, trigger_fov,com = load_config()
        with config_lock:
            old_arduino = global_config.get('arduino')
            if old_arduino and old_arduino.is_open:
                old_arduino.close()

            global_config.update({
                'arduino': new_arduino,
                'com': com,
                'aim_fov': aim_fov,
                'aim_speed_x': aim_speed_x,
                'aim_speed_y': aim_speed_y,
                'lower': lower,
                'upper': upper,
                'aim_assist': aim_assist,
                'trigger_bot': trigger_bot,
                'aim_offset': aim_offset,
                'aim_offset_x': aim_offset_x,
                'aim_key': aim_key,
                'trigger_key': trigger_key,
                'trigger_delay': trigger_delay,
                'trigger_fov':trigger_fov
            })
    except Exception as e:
        messagebox.showerror("Error", f"Error reloading config: {str(e)}")

def mousemove_aim(arduino, x=0, y=0, message=""):
    if arduino is None or not arduino.is_open:
        return
    try:
        x = int(x) if x is not None else 0
        y = int(y) if y is not None else 0
        x = x + 256 if x < 0 else x
        y = y + 256 if y < 0 else y
        x = max(0, min(x, 255))
        y = max(0, min(y, 255))
        coord_bytes = bytes([x, y])
        message_bytes = message.encode('utf-8') + b'\n'
        with arduino_lock:
            arduino.write(coord_bytes + message_bytes)
    except SerialException as e:
        messagebox.showerror("Error", f"Arduino write failed: {str(e)}")
        with config_lock:
            if global_config['arduino'].is_open:
                global_config['arduino'].close()

def run_aim_assist():
    with mss() as sct:
        while True:

            with config_lock:
                aim_assist_enabled = global_config['aim_assist']
                aim_key = global_config['aim_key']
                arduino = global_config['arduino']
                aim_fov = global_config['aim_fov']
                aim_speed_x = global_config['aim_speed_x']
                aim_speed_y = global_config['aim_speed_y']
                lower = global_config['lower']
                upper = global_config['upper']
                aim_offset = global_config['aim_offset']
                aim_offset_x = global_config['aim_offset_x']

            if aim_assist_enabled:
                aim_mid = aim_fov / 2
                aim_ass = sct.monitors[1]
                aim_ass_screen = {
                    'left': int((aim_ass['width'] / 2) - (aim_fov / 2)),
                    'top': int((aim_ass['height'] / 2) - (aim_fov / 2)),
                    'width': aim_fov,
                    'height': aim_fov,
                }

                if aim_key == 'auto' or GetAsyncKeyState(aim_key) < 0:
                    img = np.array(sct.grab(aim_ass_screen))
                    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
                    mask = cv2.inRange(hsv, lower, upper)
                    kernel = np.ones((3, 3), np.uint8)
                    dilated = cv2.dilate(mask, kernel, iterations=5)
                    thresh = cv2.threshold(dilated, 60, 255, cv2.THRESH_BINARY)[1]
                    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE)
                    
                    if contours:
                        M = cv2.moments(thresh)
                        cX = int(M["m10"] / M["m00"]) - aim_offset_x
                        cY = int(M["m01"] / M["m00"]) - aim_offset
                        x_offset = -(aim_mid - cX) if cX < aim_mid else cX - aim_mid
                        y_offset = -(aim_mid - cY) if cY < aim_mid else cY - aim_mid
                        x_move = int(round(x_offset * aim_speed_x))
                        y_move = int(round(y_offset * aim_speed_y))
                        mousemove_aim(arduino, x_move, y_move, message='movemouse')
            sleep(0.0035)

def run_trigger_bot():
   with mss() as sct:
        while True:
            with config_lock:
                trigger_enabled = global_config['trigger_bot']
                trigger_key = global_config['trigger_key']
                arduino = global_config['arduino']
                lower = global_config['lower']
                upper = global_config['upper']
                trigger_fov = global_config['trigger_fov']
                trigger_delay = global_config['trigger_delay']

            if trigger_enabled and GetAsyncKeyState(trigger_key) < 0:
                tig_ass = sct.monitors[1]
                tig_ass_screen = {
                    'left': int((tig_ass['width'] / 2) - (trigger_fov / 2)),
                    'top': int((tig_ass['height'] / 2) - (trigger_fov / 2)),
                    'width': trigger_fov,
                    'height': trigger_fov,
                }
                
                img = np.array(sct.grab(tig_ass_screen))
                hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
                mask = cv2.inRange(hsv, lower, upper)
                kernel = np.ones((3, 3), np.uint8)
                dilated = cv2.dilate(mask, kernel, iterations=5)
                thresh = cv2.threshold(dilated, 60, 255, cv2.THRESH_BINARY)[1]
                contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE)
                
                if contours:
                    sleep(float(trigger_delay))
                    mousemove_aim(arduino, message="mouseclick")
            sleep(0.0035)

def key_listener():
    while True:
        if is_pressed('f8'):
            with config_lock:
                global_config['aim_assist'] = not global_config['aim_assist']
                if global_config['aim_assist']:
                    messagebox.showinfo("Status", f"Aim Assist: ON")
                else:
                    messagebox.showinfo("Status", f"Aim Assist: OFF")
            sleep(1)
        if is_pressed('f9'):
            with config_lock:
                global_config['trigger_bot'] = not global_config['trigger_bot']
                if global_config['trigger_bot']:
                    messagebox.showinfo("Status", f"Trigger Bot: ON")
                else:
                    messagebox.showinfo("Status", f"Trigger Bot: OFF")
            sleep(1)
        if is_pressed('F10'):
            messagebox.showinfo("Status", f"Reloading configuration...")
            with config_lock:
                old_arduino = global_config['arduino']
                if old_arduino is not None and old_arduino.is_open:
                    old_arduino.close()
            new_arduino, aim_fov, aim_speed_x, aim_speed_y, lower, upper, aim_assist, trigger_bot, aim_offset, aim_offset_x, aim_key, trigger_key, trigger_fov, trigger_delay,com = load_config()
            with config_lock:
                global_config.update({
                    'arduino': new_arduino,
                    'com': com,
                    'aim_fov': aim_fov,
                    'aim_speed_x': aim_speed_x,
                    'aim_speed_y': aim_speed_y,
                    'lower': lower,
                    'upper': upper,
                    'aim_assist': aim_assist,
                    'trigger_bot': trigger_bot,
                    'aim_offset': aim_offset,
                    'aim_offset_x': aim_offset_x,
                    'aim_key': aim_key,
                    'trigger_key': trigger_key,
                    'trigger_delay':trigger_delay,
                    'trigger_fov':trigger_fov
                })
            messagebox.showinfo("Status", f"Configuration reloaded successfully!")
            sleep(1)

        sleep(0.01)

def aim_assist_loop():
    while True:
        with config_lock:
            aim_assist_enabled = global_config['aim_assist']
            aim_key = global_config['aim_key']
        if aim_assist_enabled:
            if aim_key == 'auto':
                run_aim_assist()
            else:
                if GetAsyncKeyState(aim_key) < 0:
                    run_aim_assist()
        sleep(0.01)

def trigger_bot_loop():
    while True:
        with config_lock:
            trigger_bot_enabled = global_config['trigger_bot']
            trigger_key = global_config['trigger_key']
        if trigger_bot_enabled and GetAsyncKeyState(trigger_key) < 0:
            run_trigger_bot()
        sleep(0.01)

def create_ui():
    root = tk.Tk()
    root.title("Silence Ai")
    root.geometry("450x300")
    root.overrideredirect(True)
    root.configure(bg='black')
    load_icon(root, 'BLACK.ico')
    root.attributes("-topmost", True)
    
    style = ttk.Style()
    style.theme_use('clam')
    bg_color = 'black'
    fg_color = '#FFFFFF'
    entry_bg = '#333333'
    button_bg = '#FF4444'
    active_bg = '#FF6666'
    tab_bg = '#222222'
    active_tab_bg = '#FFFFFF'

    style.configure('.', background=bg_color,foreground=fg_color, font=('Arial', 9, 'bold'))
    style.configure('TNotebook', background=bg_color, borderwidth=0)
    style.configure('TNotebook.Tab', 
                    background=tab_bg, 
                    foreground=fg_color,
                    padding=[15, 5],
                    borderwidth=0,
                    font=('Arial', 9, 'bold'))
    style.map('TNotebook.Tab',
              background=[('selected', active_tab_bg)],
              foreground=[('selected', '#000000')])
    style.configure('TCheckbutton', background='black',foreground='white')
    style.configure('TEntry', fieldbackground=entry_bg, foreground=fg_color, borderwidth=1)
    style.configure('TButton', 
                   background=button_bg, 
                   foreground=fg_color,
                   borderwidth=0,
                   focusthickness=0,
                   focuscolor=bg_color,
                   font=('Arial', 9, 'bold'),
                   padding=6)
    style.map('TButton',
              background=[('active', active_bg), ('!disabled', button_bg)],
              foreground=[('active', fg_color), ('!disabled', fg_color)])
    style.configure('TCheckbutton', background=bg_color)
    style.configure('TRadiobutton', background=bg_color)
    style.configure('Vertical.TScrollbar', background=tab_bg)
    style.configure('Horizontal.TScale', 
                   background=tab_bg,
                   troughcolor=entry_bg,
                   sliderthickness=15)
    style.configure('TOptionMenu',
                background=bg_color,
                foreground=fg_color,
                fieldbackground=entry_bg)
    style.configure('TCheckbutton',
                    background=bg_color,
                    foreground=fg_color)
    style.map('TCheckbutton',
              background=[('active', bg_color),
                          ('selected', bg_color)])

    title_bar = tk.Frame(root, bg='black', relief='raised', bd=0)
    title_bar.pack(fill='x', side='top')
    icon_image = Image.open(get_resource_path('BLACK.ico'))
    icon_image = icon_image.resize((50, 50))
    title_image = ImageTk.PhotoImage(icon_image)
    title_label = tk.Label(title_bar, image=title_image, bg='black')
    title_label.pack(side='left', padx=5)
    
    def show_window():
        root.after(0, root.deiconify)

    def hide_window():
        root.after(0, root.withdraw)

    def exit_app(icon):
        icon.stop()
        with config_lock:
            if global_config['arduino'].is_open:
                global_config['arduino'].close()
        root.destroy()

    tray_image = Image.open(get_resource_path('BLACK.ico'))
    menu = (
        item('Show', show_window),
        item('Hide', hide_window),
        item('Exit', exit_app)
    )
    icon = pystray.Icon("Silence Ai", tray_image, "Silence Ai", menu)
    Thread(target=icon.run, daemon=True).start()

    def on_drag(event):
        root.geometry(f'+{event.x_root}+{event.y_root}')
    def close_window():
        root.quit()
        root.destroy()

    def minimize_window():
        root.withdraw()

    title_bar.bind("<B1-Motion>", on_drag)
    close_button = tk.Button(title_bar, text='X', command=close_window, bg='black', fg='white', relief='flat', bd=0, font=('Arial', 12, 'bold'), highlightthickness=0,cursor='hand2')
    close_button.pack(side='right', padx=5)

    minimize_button = tk.Button(title_bar, text='-', command=minimize_window, bg='black', fg='white', relief='flat', bd=0, font=('Arial', 12, 'bold'), highlightthickness=0,cursor='hand2')
    minimize_button.pack(side='right', padx=5)

    config = ConfigParser()
    config.read('config.ini')

    notebook = ttk.Notebook(root)
    settings_frame = ttk.Frame(notebook)
    aim_frame = ttk.Frame(notebook)
    trigger_frame = ttk.Frame(notebook)
    custom_frame = ttk.Frame(notebook)
    notebook.add(settings_frame, text='Settings')
    notebook.add(aim_frame, text='Aim')
    notebook.add(trigger_frame, text='Trigger')
    notebook.add(custom_frame, text='Custom')
    notebook.pack(expand=1, fill='both')

    com_port = tk.StringVar(value=config.get('Settings', 'com_port'))
    color = tk.StringVar(value=config.get('Settings', 'color'))
    aim_key = tk.StringVar(value=config.get('Settings', 'aim_key'))
    trigger_key = tk.StringVar(value=config.get('Settings', 'trigger_key'))
    aim_assist = tk.BooleanVar(value=config.getboolean('Settings', 'aim_assist'))
    trigger_bot = tk.BooleanVar(value=config.getboolean('Settings', 'trigger_bot'))

    aim_fov = tk.IntVar(value=config.getint('Aim', 'aim_fov'))
    aim_offset = tk.StringVar(value=config.get('Aim', 'aim_offset'))
    aim_speed_x = tk.DoubleVar(value=config.getfloat('Aim', 'aim_speed_x'))
    aim_speed_y = tk.DoubleVar(value=config.getfloat('Aim', 'aim_speed_y'))

    trigger_fov = tk.IntVar(value=config.getint('Trigger', 'trigger_fov'))
    trigger_delay = tk.DoubleVar(value=config.getfloat('Trigger', 'trigger_delay'))

    custom_lower = [int(x) for x in config.get('Custom', 'custom_lower').split(',')]
    custom_upper = [int(x) for x in config.get('Custom', 'custom_upper').split(',')]
    custom_lower_h = tk.IntVar(value=custom_lower[0])
    custom_lower_s = tk.IntVar(value=custom_lower[1])
    custom_lower_v = tk.IntVar(value=custom_lower[2])
    custom_upper_h = tk.IntVar(value=custom_upper[0])
    custom_upper_s = tk.IntVar(value=custom_upper[1])
    custom_upper_v = tk.IntVar(value=custom_upper[2])
    custom_offset_x = tk.IntVar(value=config.getint('Custom', 'custom_offset_x'))
    custom_offset_y = tk.IntVar(value=config.getint('Custom', 'custom_offset_y'))

    def spoof_arduino():
        messagebox.showinfo("Status", f"Spoofing Arduino.....")
        hex_path = get_resource_path('Silence.hex')
        avrdude_path = get_resource_path('avrdude.exe')
        com = global_config['com']
        with config_lock:
            if global_config.get('arduino') and global_config['arduino'].is_open:
                global_config['arduino'].close()

        command = [
            avrdude_path, 
            "-c", "avr109", 
            "-v", 
            "-P", com,
            "-b", "115200", 
            "-p", "atmega32u4", 
            "-D", 
            "-U", f"flash:w:{hex_path}:i"
        ]

        try:
            try:
                test = Serial(com, 115200, timeout=1)
                test.close()
            except SerialException:
                messagebox.showerror("Port Error",
                    f"COM port {com} not available!\n"
                    "1. Make sure Arduino is connected\n"
                    "2. Close all serial monitor programs\n"
                    "3. Disconnect from Arduino in other apps")
                return
            result = run(command, 
                                  capture_output=True, 
                                  text=True,
                                  creationflags=CREATE_NO_WINDOW)

            if result.returncode == 0:
                messagebox.showinfo("Success",
                    "Flashing completed!\n\n"
                    "NEXT STEPS:\n"
                    "1. Physically unplug the device\n"
                    "2. Wait 5 seconds\n"
                    "3. Plug it back in\n"
                    "4. Check Device Manager for new COM port\n"
                    "5. Update COM port in settings if changed")
            else:
                error_msg = f"Flashing failed (code {result.returncode})\n\n"
                error_msg += f"Error output:\n{result.stderr}\n"
                error_msg += f"Debug info:\n{result.stdout}"
                messagebox.showerror("Flashing Failed", error_msg)

        except Exception as e:
            messagebox.showerror("Critical Error", 
                f"Failed to execute programmer: {str(e)}\n"
                "Make sure:\n"
                "- Arduino is in bootloader mode\n"
                "- Correct USB cable is used (data capable)\n"
                "- Drivers are properly installed")
        finally:
            initialize_global_config()

    def save_config():
        try:
            config['Settings']['com_port'] = com_port.get()
            config['Settings']['color'] = color.get()
            config['Settings']['aim_key'] = aim_key.get()
            config['Settings']['trigger_key'] = trigger_key.get()
            config['Settings']['aim_assist'] = str(aim_assist.get())
            config['Settings']['trigger_bot'] = str(trigger_bot.get())

            config['Aim']['aim_fov'] = str(aim_fov.get())
            config['Aim']['aim_offset'] = aim_offset.get()
            config['Aim']['aim_speed_x'] = f"{aim_speed_x.get():.2f}"
            config['Aim']['aim_speed_y'] = f"{aim_speed_y.get():.2f}"

            config['Trigger']['trigger_fov'] = str(trigger_fov.get())
            config['Trigger']['trigger_delay'] = f"{trigger_delay.get():.2f}"

            config['Custom']['custom_lower'] = f"{custom_lower_h.get()}, {custom_lower_s.get()}, {custom_lower_v.get()}"
            config['Custom']['custom_upper'] = f"{custom_upper_h.get()}, {custom_upper_s.get()}, {custom_upper_v.get()}"
            config['Custom']['custom_offset_x'] = str(custom_offset_x.get())
            config['Custom']['custom_offset_y'] = str(custom_offset_y.get())

            with open('config.ini', 'w') as f:
                config.write(f)
            
            with config_lock:
                old_arduino = global_config.get('arduino')
                if old_arduino and old_arduino.is_open:
                    old_arduino.close()

            initialize_global_config()
            messagebox.showinfo("Success", "Configuration saved and applied!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {str(e)}")

    ttk.Label(settings_frame, text="COM Port:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
    ttk.Entry(settings_frame, textvariable=com_port, width=10).grid(row=0, column=1, padx=10, pady=5)
    
    ttk.Label(settings_frame, text="Color:").grid(row=0, column=2, padx=10, pady=5, sticky='w')
    color_option = ttk.OptionMenu(settings_frame, color, color.get(), 'yellow', 'yellow 2', 'purple', 'anti astra', 'red', 'custom')
    color_option.config(width=10)
    color_option.grid(row=0, column=3, pady=5, sticky='ew')
    
    ttk.Label(settings_frame, text="Aim Key:").grid(row=1, column=0, padx=10, pady=5, sticky='w')
    ttk.Entry(settings_frame, textvariable=aim_key, width=10).grid(row=1, column=1, padx=10, pady=5)
    
    ttk.Label(settings_frame, text="Trigger Key:").grid(row=1, column=2, padx=10, pady=5, sticky='w')
    ttk.Entry(settings_frame, textvariable=trigger_key, width=10).grid(row=1, column=3, padx=10, pady=5)
    
    ttk.Checkbutton(settings_frame, text="Aim Assist", variable=aim_assist).grid(row=4, column=0, padx=10, pady=5, sticky='w')
    ttk.Checkbutton(settings_frame, text="Trigger Bot", variable=trigger_bot).grid(row=4, column=1, padx=10, pady=5, sticky='w')
    
    ttk.Button(settings_frame, text="⚡ Spoof Arduino", command=spoof_arduino).grid(row=5, column=0, columnspan=2, pady=15, sticky='ew', padx=20)

    ttk.Label(aim_frame, text="Aim FOV:").grid(row=0, column=0, sticky='w', padx=5)
    tk.Scale(aim_frame, from_=0, to=200, variable=aim_fov, orient='horizontal').grid(row=0, column=1, padx=5, pady=2)
    ttk.Label(aim_frame, textvariable=aim_fov).grid(row=0, column=2, padx=5)
    ttk.Label(aim_frame, text="Aim Offset:").grid(row=1, column=0, sticky='w', padx=5)
    ttk.OptionMenu(aim_frame, aim_offset, aim_offset.get(), 'head', 'neck', 'body', 'custom').grid(row=1, column=1, padx=5, pady=2)
    ttk.Label(aim_frame, text="Aim Speed X:").grid(row=2, column=0, sticky='w', padx=5)
    tk.Scale(aim_frame, from_=0.0, to=1.0, variable=aim_speed_x, resolution=0.01, orient='horizontal').grid(row=2, column=1, padx=5, pady=2)
    ttk.Label(aim_frame, textvariable=aim_speed_x).grid(row=2, column=2, padx=5)
    ttk.Label(aim_frame, text="Aim Speed Y:").grid(row=3, column=0, sticky='w', padx=5)
    tk.Scale(aim_frame, from_=0.0, to=1.0, variable=aim_speed_y, resolution=0.01, orient='horizontal').grid(row=3, column=1, padx=5, pady=2)
    ttk.Label(aim_frame, textvariable=aim_speed_y).grid(row=3, column=2, padx=5)

    ttk.Label(trigger_frame, text="Trigger FOV:").grid(row=0, column=0, sticky='w', padx=5)
    tk.Scale(trigger_frame, from_=0, to=50, variable=trigger_fov, orient='horizontal').grid(row=0, column=1, padx=5, pady=2)
    ttk.Label(trigger_frame, textvariable=trigger_fov).grid(row=0, column=2, padx=5)
    ttk.Label(trigger_frame, text="Trigger Delay:").grid(row=1, column=0, sticky='w', padx=5)
    tk.Scale(trigger_frame, from_=0.0, to=1.0, variable=trigger_delay, resolution=0.01, orient='horizontal').grid(row=1, column=1, padx=5, pady=2)
    ttk.Label(trigger_frame, textvariable=trigger_delay).grid(row=1, column=2, padx=5)

    ttk.Label(custom_frame, text="Lower HSV (H, S, V):").grid(row=0, column=0, columnspan=3, sticky='w', padx=5)
    ttk.Scale(custom_frame, from_=0, to=179, variable=custom_lower_h, orient='horizontal').grid(row=1, column=0, padx=5, pady=2)
    ttk.Scale(custom_frame, from_=0, to=255, variable=custom_lower_s, orient='horizontal').grid(row=1, column=1, padx=5, pady=2)
    ttk.Scale(custom_frame, from_=0, to=255, variable=custom_lower_v, orient='horizontal').grid(row=1, column=2, padx=5, pady=2)
    ttk.Label(custom_frame, text="Upper HSV (H, S, V):").grid(row=2, column=0, columnspan=3, sticky='w', padx=5)
    ttk.Scale(custom_frame, from_=0, to=179, variable=custom_upper_h, orient='horizontal').grid(row=3, column=0, padx=5, pady=2)
    ttk.Scale(custom_frame, from_=0, to=255, variable=custom_upper_s, orient='horizontal').grid(row=3, column=1, padx=5, pady=2)
    ttk.Scale(custom_frame, from_=0, to=255, variable=custom_upper_v, orient='horizontal').grid(row=3, column=2, padx=5, pady=2)
    ttk.Label(custom_frame, text="Custom Offset (X, Y):").grid(row=4, column=0, columnspan=3, sticky='w', padx=5)
    ttk.Entry(custom_frame, textvariable=custom_offset_x).grid(row=5, column=0, padx=5, pady=2)
    ttk.Entry(custom_frame, textvariable=custom_offset_y).grid(row=5, column=1, padx=5, pady=2)

    ttk.Button(root, text="Save & Apply", command=save_config).pack(pady=5)

    def on_closing():
        with config_lock:
            if global_config['arduino'] is not None:
                global_config['arduino'].close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

class LoadingScreen(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Silence Ai")
        self.geometry("400x250")
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg='black')
        icon_path = get_resource_path('BLACK.ico')
        load_icon(self, icon_path)
        top_frame = tk.Frame(self, bg='black', relief='flat', bd=0)
        top_frame.pack(fill='x')
        close_button = tk.Button(top_frame, text="X", command=self.on_closing, fg='white', bg='black', font=('Arial', 12, 'bold'), bd=0, highlightthickness=0,cursor='hand2')
        close_button.pack(side='right')
        self.status_var = tk.StringVar()
        self.label = tk.Label(self, textvariable=self.status_var, font=('Copperplate Gothic', 12, 'bold'), fg='cyan', bg='black')
        self.label.pack(pady=20, expand=True)
        self.image = Image.open(get_resource_path('BLACK.ico'))
        self.image = self.image.resize((50, 50))
        self.image = ImageTk.PhotoImage(self.image)
        self.image_label = tk.Label(self, image=self.image, bg='black')
        self.image_label.place(x=10, y=10) 
        self.queue = queue.Queue()
        self.access_granted = False
        self.check_queue()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        top_frame.bind('<B1-Motion>', self.on_drag)
    
    def on_minimize(self):
        self.withdraw()
    def on_closing(self):
        self.destroy()
    def on_drag(self, event):
        self.geometry(f'+{event.x_root}+{event.y_root}')
            
    def check_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                if isinstance(msg, tuple):
                    if msg[0] == "status":
                        self.status_var.set(msg[1])
                    elif msg[0] == "error":
                        messagebox.showerror("Error", msg[1])
                        self.destroy()
                        _exit(0)
                    elif msg[0] == "result":
                        self.access_granted = msg[1]
                        if self.access_granted:
                            self.after(2000, self.destroy)
                        else:
                            self.after(0, self.destroy)
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def on_closing(self):
        self.destroy()
        _exit(0)

def loading(queue):
    global session_token

    queue.put(("status", "Initializing security systems..."))
    send_discord_webhook("Try To Login",16776960)
    sleep(1)
    if not perform_security_checks(queue):
        sleep(2)
        _exit(0)
    
    queue.put(("status", "Security checks passed"))
    sleep(1)

    try:
        auth_data = {
            "hwid": get_hwid(),
            "version": version,
            "app": app
        }
        encrypted_request = encrypt_data(auth_data)
        auth_response = post(auth_server, headers=auth_headers, data=json.dumps(encrypted_request), timeout=10)
        response_data = auth_response.json()
        if 'data' not in response_data or 'iv' not in response_data:
            raise ValueError("Invalid encrypted response format")
        decrypted = decrypt_response(response_data['data'], response_data['iv'])
        if 'error' in decrypted:
            queue.put(("error", f"Authorization failed: {decrypted['error']}"))
            send_discord_webhook("Login Failed", 16711680)
            queue.put(("result", False))
        elif 'success' in decrypted:
            queue.put(("status", "Access granted"))
            session_token = decrypted['sessionToken']
            send_discord_webhook("Login Success", 65280)
            queue.put(("result", True))
        else:
            queue.put(("error", "Invalid server response"))
            send_discord_webhook("Login Failed", 16711680)
            queue.put(("result", False))
    except exceptions.HTTPError as e:
        error_msg = f"HTTP error: {str(e)}"
        queue.put(("error", error_msg))
        send_discord_webhook("Login Failed", 16711680)
        queue.put(("result", False))
    except (json.JSONDecodeError, ValueError) as e:
        error_msg = f"Invalid server response: {str(e)}"
        queue.put(("error", error_msg))
        send_discord_webhook("Login Failed", 16711680)
        queue.put(("result", False))
    except Exception as e:
        error_msg = f"Connection error: {str(e)}"
        queue.put(("error", error_msg))
        send_discord_webhook("Login Failed", 16711680)
        queue.put(("result", False))

def send_discord_webhook(action_value, color):
    webhook_url = "https://auth-a6s.pages.dev/webhook"
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    embed = {
        "title": "Loader Logs",
        "color": color,
        "fields": [
            {
                "name": "Action",
                "value": f"***{action_value}***",
                "inline": False
            },
            {
                "name": "HWID",
                "value": f"***{get_hwid()}***",
                "inline": False
            },
            {
                "name": "Version",
                "value": f"v***{version}***",
                "inline": True
            },
            {
                "name": "App",
                "value": f"***{app}***",
                "inline": True
            }
        ],
        "footer": {
            "text": f"{current_time}"
        }
    }
    
    webhook_data = {
        "embeds": [embed]
    }
    response = post(webhook_url, json=webhook_data)
    return response.status_code, response.text

if __name__ == "__main__":

    if is_debugger_present() or check_debugger_processes() or is_vm():
        send_discord_webhook("Security violation detected!",16734208)
        _exit(0)

    loading_screen = LoadingScreen()
    loading_thread = Thread(target=loading, args=(loading_screen.queue,), daemon=True)
    loading_thread.start()
    loading_screen.mainloop()

    if not loading_screen.access_granted:
        _exit(0)
    
    def security_monitor():
        while True:
            if is_debugger_present() or check_debugger_processes() or is_vm():
                send_discord_webhook("Runtime security violation detected!",16734208)
                _exit(0)
            sleep(5)

    security_thread = Thread(target=security_monitor, daemon=True)
    security_thread.start()

    initialize_global_config()

    key_thread = Thread(target=key_listener, daemon=True)
    aim_thread = Thread(target=aim_assist_loop, daemon=True)
    trigger_thread = Thread(target=trigger_bot_loop, daemon=True)
    check_thread = Thread(target=check, daemon=True)

    key_thread.start()
    aim_thread.start()
    trigger_thread.start()
    check_thread.start()
    create_ui()