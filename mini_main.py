_A6='WM_DELETE_WINDOW'
_A5='<B1-Motion>'
_A4='anti astra'
_A3='Invalid encrypted response format'
_A2='sessionToken'
_A1='right'
_A0='hand2'
_z='flat'
_y='top'
_x='left'
_w='aim_offset_x'
_v='com'
_u='custom_upper'
_t='custom_lower'
_s='custom_offset_x'
_r='custom_offset_y'
_q='com_port'
_p='utf-8'
_o='status'
_n='white'
_m='height'
_l='width'
_k='upper'
_j='lower'
_i='color'
_h='custom'
_g='BLACK.ico'
_f='auto'
_e='Error'
_d='config.ini'
_c='iv'
_b='data'
_a='Silence Ai'
_Z='Arial'
_Y='aim_offset'
_X='trigger_fov'
_W='trigger_delay'
_V='aim_speed_y'
_U='aim_speed_x'
_T='aim_fov'
_S='name'
_R='result'
_Q='bold'
_P='Status'
_O='trigger_key'
_N='aim_key'
_M='Trigger'
_L='trigger_bot'
_K='aim_assist'
_J=None
_I='black'
_H='Custom'
_G='Aim'
_F='error'
_E='w'
_D='arduino'
_C=False
_B='Settings'
_A=True
from ctypes import windll
import cv2
from mss import mss
import numpy as np
from keyboard import is_pressed
import serial.tools.list_ports
from serial import Serial,SerialException
from time import sleep
from configparser import ConfigParser
from os import _exit,path,getcwd,urandom
from colorama import Fore
from win32api import GetAsyncKeyState,GetLongPathName
from threading import Lock,Thread
from hwid import get_hwid
from requests import post
from requests import exceptions
from json import dumps
from datetime import datetime
from subprocess import CREATE_NO_WINDOW,run
import tkinter as tk
from tkinter import ttk,messagebox
import queue
from PIL import Image,ImageTk
import pystray
from pystray import MenuItem as item
import hashlib
from winreg import HKEY_LOCAL_MACHINE,OpenKey,QueryValueEx,CloseKey
from uuid import getnode
from psutil import process_iter,cpu_count
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64,json
def get_resource_path(relative_path):
	C=relative_path;A=[]
	if getattr(sys,'_MEIPASS',_J):A.append(sys._MEIPASS)
	A.append(path.dirname(path.abspath(sys.argv[0])));A.append(path.dirname(path.abspath(__file__)));A.append(getcwd())
	for D in A:
		B=path.join(D,C)
		if path.exists(B):
			try:B=GetLongPathName(B)
			except ImportError:pass
			except Exception as E:print(f"Path conversion error: {str(E)}")
			return B
	return path.abspath(C)
def load_icon(window,icon_name):
	A=window;B=get_resource_path(icon_name)
	try:A.iconbitmap(B)
	except tk.TclError:C=path.abspath(B);A.tk.call('wm','iconbitmap',A._w,f"@{C}")
def get_file_hash():
	try:
		if getattr(sys,'frozen',_C):A=sys.executable
		else:A=__file__
		B=hashlib.sha256()
		with open(A,'rb')as D:
			while _A:
				C=D.read(4096)
				if not C:break
				B.update(C)
		return B.hexdigest()
	except Exception as E:return'ERROR'
def is_debugger_present():return windll.kernel32.IsDebuggerPresent()!=0
def check_debugger_processes():
	A=['ollydbg.exe','ida64.exe','idaq.exe','windbg.exe','x32dbg.exe','x64dbg.exe','dbgview.exe','procmon.exe','wireshark.exe']
	try:
		for B in process_iter([_S]):
			if B.info[_S].lower()in A:return _A
		return _C
	except Exception:return _C
def check_vm_registry():
	try:A=OpenKey(HKEY_LOCAL_MACHINE,'HARDWARE\\DESCRIPTION\\System\\BIOS');B=QueryValueEx(A,'SystemManufacturer')[0].lower();C=QueryValueEx(A,'SystemProductName')[0].lower();CloseKey(A);D=['vmware','virtual','qemu','xen','kvm','hyper-v'];return any(A in B or A in C for A in D)
	except Exception:return _C
def check_vm_files():A=['C:\\Windows\\System32\\Drivers\\Vmmouse.sys','C:\\Windows\\System32\\Drivers\\vm3dgl.dll','C:\\Windows\\System32\\Drivers\\vmdum.dll','C:\\Windows\\System32\\Drivers\\vm3dver.dll','C:\\Windows\\System32\\Drivers\\vmci.sys','C:\\Windows\\System32\\vboxhook.dll'];return any(path.exists(A)for A in A)
def check_vm_mac():A=getnode();B=[A>>B&255 for B in range(0,8*6,8)][::-1];C=':'.join(['{:02x}'.format(A)for A in B]);D=['00:05:69','00:0c:29','00:1c:14','00:50:56','08:00:27','0a:00:27'];return any(C.startswith(A)for A in D)
def check_cpu_cores():return cpu_count(logical=_C)<2
def is_vm():return check_vm_registry()or check_vm_files()or check_vm_mac()or check_cpu_cores()
def perform_security_checks(queue):
	D='Virtual machine detected!';C='Debugging tools detected!';B='Debugger detected!';A=queue
	if is_debugger_present():send_discord_webhook(B,16734208);A.put((_F,B));return _C
	if check_debugger_processes():send_discord_webhook(C,16734208);A.put((_F,C));return _C
	if is_vm():send_discord_webhook(D,16734208);A.put((_F,D));return _C
	try:get_file_hash()
	except Exception as E:send_discord_webhook('Integrity check failed!',16734208);A.put((_F,f"Integrity check failed: {str(E)}"));return _C
	return _A
def detect_arduino_port():
	try:
		C=serial.tools.list_ports.comports()
		for A in C:
			B=A.description.lower()
			if _D in B or'usb serial device'in B:return A.device
		raise SerialException('No Arduino or USB Serial Device found')
	except Exception as D:raise SerialException(f"Port detection error: {str(D)}")
windll.kernel32.SetConsoleTitleW(_a)
default_config="\n[Settings]\n# COM Port for Arduino (use 'auto' for auto detect)\ncom_port = auto\n\n# Color for detection (options: yellow, yellow 2, purple, anti astra, red, custom)\ncolor = purple\n\n# Virtual Key Code (https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes) (use 'auto' for auto aim)\naim_key = auto\ntrigger_key = 0x05\n\n# Enabled by default (True/False)\naim_assist = False\ntrigger_bot = False\n\n[Aim]\n# Field of View for the Aim Assist (in pixels)\naim_fov = 65\n\n# Aim Offset ( head, neck, body, custom)\naim_offset = head\n\n# Aim Speed settings (X and Y axis)\naim_speed_x = 0.6\naim_speed_y = 0.3\n\n[Trigger]\n# Field of View for the Trigger Bot (in pixels)\ntrigger_fov = 8\n\n# Trigger Delay (in milliseconds)\ntrigger_delay = 0.2\n\n[Custom]\n# Define the color ranges for detection (HSV values)\ncustom_lower = 23, 78, 199\ncustom_upper = 32, 255, 254\n\n# Define custom Offset\ncustom_offset_y = 3\ncustom_offset_x = 0\n"
global_config={}
config_lock=Lock()
arduino_lock=Lock()
ENCRYPTION_KEY=base64.b64decode('ZDqZYXkGJOXuHWFTyPhct0kYzKvLlKbSXC8GbwM+9kw=')
version='1.0.1'
app='silence-color'
session_token=_J
auth_server='https://auth-a6s.pages.dev/check'
auth_check='https://auth-a6s.pages.dev/renew-session'
auth_headers={'Content-Type':'application/json','X-Encrypted':'true'}
def encrypt_data(plaintext_data):
	try:A=urandom(12);B=json.dumps(plaintext_data).encode(_p);C=AESGCM(ENCRYPTION_KEY);D=C.encrypt(A,B,_J);return{_b:D.hex(),_c:A.hex()}
	except Exception as E:raise Exception(f"Encryption failed: {str(E)}")
def decrypt_response(encrypted_hex,iv_hex):
	try:A=bytes.fromhex(encrypted_hex);B=bytes.fromhex(iv_hex);C=AESGCM(ENCRYPTION_KEY);D=C.decrypt(B,A,_J);return json.loads(D.decode(_p))
	except Exception as E:return{_F:f"Decryption failed: {str(E)}"}
def check():
	B={'hwid':get_hwid(),'version':version,'app':app,_A2:session_token}
	while _A:
		C=encrypt_data(B);D=post(auth_check,headers=auth_headers,data=dumps(C),timeout=10);A=D.json()
		if _b not in A or _c not in A:raise ValueError(_A3)
		E=decrypt_response(A[_b],A[_c])
		if _F in E:_exit(0)
		sleep(250)
def create_default_config():
	with open(_d,_E)as A:A.write(default_config)
	messagebox.showinfo(_e,f"Config not found. Creating default config.ini.")
def load_config():
	A=ConfigParser()
	if not path.exists(_d):create_default_config()
	A.read(_d);I=A[_B][_q];J=_J
	try:
		if I.strip().lower()==_f:G=detect_arduino_port()
		else:G=I
		J=Serial(G,115200,timeout=1)
	except SerialException as H:messagebox.showerror('Initialization Error',f"Failed to initialize Arduino: {str(H)}");raise
	except Exception as H:messagebox.showerror('Unexpected error',f"{str(H)}");raise
	N=int(A[_G][_T]);O=float(A[_G][_U]);P=float(A[_G][_V]);Q=float(A[_M][_W]);R=int(A[_M][_X]);K=A[_B][_N]
	if K.strip().lower()==_f:L=_f
	else:L=int(K,16)
	S=int(A[_B][_O],16);F=A[_G][_Y];M=0
	if F=='head':E=8
	elif F=='neck':E=6
	elif F=='body':E=2
	elif F==_h:E=int(A[_H][_r]);M=int(A[_H][_s])
	else:E=8
	D=A[_B][_i]
	if D=='yellow':B=np.array([30,125,150]);C=np.array([30,255,255])
	elif D=='yellow 2':B=np.array([30,170,254]);C=np.array([30,230,255])
	elif D=='purple':B=np.array([144,72,150]);C=np.array([152,255,255])
	elif D==_A4:B=np.array([135,95,200]);C=np.array([155,255,255])
	elif D=='red':B=np.array([0,170,150]);C=np.array([5,255,255])
	elif D==_h:B=np.array([int(A)for A in A[_H][_t].split(',')]);C=np.array([int(A)for A in A[_H][_u].split(',')])
	else:B=np.array([144,72,150]);C=np.array([152,255,255])
	T=A.getboolean(_B,_K);U=A.getboolean(_B,_L);return J,N,O,P,B,C,T,U,E,M,L,S,Q,R,G
def initialize_global_config():
	try:
		B,C,D,E,F,G,H,I,J,K,L,M,N,O,P=load_config()
		with config_lock:
			A=global_config.get(_D)
			if A and A.is_open:A.close()
			global_config.update({_D:B,_v:P,_T:C,_U:D,_V:E,_j:F,_k:G,_K:H,_L:I,_Y:J,_w:K,_N:L,_O:M,_W:N,_X:O})
	except Exception as Q:messagebox.showerror(_e,f"Error reloading config: {str(Q)}")
def mousemove_aim(arduino,x=0,y=0,message=''):
	A=arduino
	if A is _J or not A.is_open:return
	try:
		x=int(x)if x is not _J else 0;y=int(y)if y is not _J else 0;x=x+256 if x<0 else x;y=y+256 if y<0 else y;x=max(0,min(x,255));y=max(0,min(y,255));B=bytes([x,y]);C=message.encode(_p)+b'\n'
		with arduino_lock:A.write(B+C)
	except SerialException as D:
		messagebox.showerror(_e,f"Arduino write failed: {str(D)}")
		with config_lock:
			if global_config[_D].is_open:global_config[_D].close()
def run_aim_assist():
	J='m00'
	with mss()as F:
		while _A:
			with config_lock:K=global_config[_K];G=global_config[_N];L=global_config[_D];B=global_config[_T];M=global_config[_U];N=global_config[_V];O=global_config[_j];P=global_config[_k];Q=global_config[_Y];R=global_config[_w]
			if K:
				A=B/2;H=F.monitors[1];S={_x:int(H[_l]/2-B/2),_y:int(H[_m]/2-B/2),_l:B,_m:B}
				if G==_f or GetAsyncKeyState(G)<0:
					T=np.array(F.grab(S));U=cv2.cvtColor(T,cv2.COLOR_BGR2HSV);V=cv2.inRange(U,O,P);W=np.ones((3,3),np.uint8);X=cv2.dilate(V,W,iterations=5);I=cv2.threshold(X,60,255,cv2.THRESH_BINARY)[1];Y,d=cv2.findContours(I,cv2.RETR_EXTERNAL,cv2.CHAIN_APPROX_NONE)
					if Y:C=cv2.moments(I);D=int(C['m10']/C[J])-R;E=int(C['m01']/C[J])-Q;Z=-(A-D)if D<A else D-A;a=-(A-E)if E<A else E-A;b=int(round(Z*M));c=int(round(a*N));mousemove_aim(L,b,c,message='movemouse')
			sleep(.0035)
def run_trigger_bot():
	with mss()as B:
		while _A:
			with config_lock:D=global_config[_L];E=global_config[_O];F=global_config[_D];G=global_config[_j];H=global_config[_k];A=global_config[_X];I=global_config[_W]
			if D and GetAsyncKeyState(E)<0:
				C=B.monitors[1];J={_x:int(C[_l]/2-A/2),_y:int(C[_m]/2-A/2),_l:A,_m:A};K=np.array(B.grab(J));L=cv2.cvtColor(K,cv2.COLOR_BGR2HSV);M=cv2.inRange(L,G,H);N=np.ones((3,3),np.uint8);O=cv2.dilate(M,N,iterations=5);P=cv2.threshold(O,60,255,cv2.THRESH_BINARY)[1];Q,R=cv2.findContours(P,cv2.RETR_EXTERNAL,cv2.CHAIN_APPROX_NONE)
				if Q:sleep(float(I));mousemove_aim(F,message='mouseclick')
			sleep(.0035)
def key_listener():
	while _A:
		if is_pressed('f8'):
			with config_lock:
				global_config[_K]=not global_config[_K]
				if global_config[_K]:messagebox.showinfo(_P,f"Aim Assist: ON")
				else:messagebox.showinfo(_P,f"Aim Assist: OFF")
			sleep(1)
		if is_pressed('f9'):
			with config_lock:
				global_config[_L]=not global_config[_L]
				if global_config[_L]:messagebox.showinfo(_P,f"Trigger Bot: ON")
				else:messagebox.showinfo(_P,f"Trigger Bot: OFF")
			sleep(1)
		if is_pressed('F10'):
			messagebox.showinfo(_P,f"Reloading configuration...")
			with config_lock:
				A=global_config[_D]
				if A is not _J and A.is_open:A.close()
			B,C,D,E,F,G,H,I,J,K,L,M,N,O,P=load_config()
			with config_lock:global_config.update({_D:B,_v:P,_T:C,_U:D,_V:E,_j:F,_k:G,_K:H,_L:I,_Y:J,_w:K,_N:L,_O:M,_W:O,_X:N})
			messagebox.showinfo(_P,f"Configuration reloaded successfully!");sleep(1)
		sleep(.01)
def aim_assist_loop():
	while _A:
		with config_lock:B=global_config[_K];A=global_config[_N]
		if B:
			if A==_f:run_aim_assist()
			elif GetAsyncKeyState(A)<0:run_aim_assist()
		sleep(.01)
def trigger_bot_loop():
	while _A:
		with config_lock:A=global_config[_L];B=global_config[_O]
		if A and GetAsyncKeyState(B)<0:run_trigger_bot()
		sleep(.01)
def create_ui():
	w='Success';v='!disabled';u='TButton';t='TNotebook.Tab';s='#FFFFFF';c=1.;b=.0;a='active';Z='selected';M='TCheckbutton';G='horizontal';B=tk.Tk();B.title(_a);B.geometry('450x300');B.overrideredirect(_A);B.configure(bg=_I);load_icon(B,_g);B.attributes('-topmost',_A);C=ttk.Style();C.theme_use('clam');H=_I;J=s;N='#333333';d='#FF4444';x='#FF6666';O='#222222';y=s;C.configure('.',background=H,foreground=J,font=(_Z,9,_Q));C.configure('TNotebook',background=H,borderwidth=0);C.configure(t,background=O,foreground=J,padding=[15,5],borderwidth=0,font=(_Z,9,_Q));C.map(t,background=[(Z,y)],foreground=[(Z,'#000000')]);C.configure(M,background=_I,foreground=_n);C.configure('TEntry',fieldbackground=N,foreground=J,borderwidth=1);C.configure(u,background=d,foreground=J,borderwidth=0,focusthickness=0,focuscolor=H,font=(_Z,9,_Q),padding=6);C.map(u,background=[(a,x),(v,d)],foreground=[(a,J),(v,J)]);C.configure(M,background=H);C.configure('TRadiobutton',background=H);C.configure('Vertical.TScrollbar',background=O);C.configure('Horizontal.TScale',background=O,troughcolor=N,sliderthickness=15);C.configure('TOptionMenu',background=H,foreground=J,fieldbackground=N);C.configure(M,background=H,foreground=J);C.map(M,background=[(a,H),(Z,H)]);L=tk.Frame(B,bg=_I,relief='raised',bd=0);L.pack(fill='x',side=_y);P=Image.open(get_resource_path(_g));P=P.resize((50,50));z=ImageTk.PhotoImage(P);A0=tk.Label(L,image=z,bg=_I);A0.pack(side=_x,padx=5)
	def A1():B.after(0,B.deiconify)
	def A2():B.after(0,B.withdraw)
	def A3(icon):
		icon.stop()
		with config_lock:
			if global_config[_D].is_open:global_config[_D].close()
		B.destroy()
	A4=Image.open(get_resource_path(_g));A5=item('Show',A1),item('Hide',A2),item('Exit',A3);A6=pystray.Icon(_a,A4,_a,A5);Thread(target=A6.run,daemon=_A).start()
	def A7(event):A=event;B.geometry(f"+{A.x_root}+{A.y_root}")
	def A8():B.quit();B.destroy()
	def A9():B.withdraw()
	L.bind(_A5,A7);AA=tk.Button(L,text='X',command=A8,bg=_I,fg=_n,relief=_z,bd=0,font=(_Z,12,_Q),highlightthickness=0,cursor=_A0);AA.pack(side=_A1,padx=5);AB=tk.Button(L,text='-',command=A9,bg=_I,fg=_n,relief=_z,bd=0,font=(_Z,12,_Q),highlightthickness=0,cursor=_A0);AB.pack(side=_A1,padx=5);A=ConfigParser();A.read(_d);I=ttk.Notebook(B);D=ttk.Frame(I);E=ttk.Frame(I);K=ttk.Frame(I);F=ttk.Frame(I);I.add(D,text=_B);I.add(E,text=_G);I.add(K,text=_M);I.add(F,text=_H);I.pack(expand=1,fill='both');e=tk.StringVar(value=A.get(_B,_q));Q=tk.StringVar(value=A.get(_B,_i));f=tk.StringVar(value=A.get(_B,_N));g=tk.StringVar(value=A.get(_B,_O));h=tk.BooleanVar(value=A.getboolean(_B,_K));i=tk.BooleanVar(value=A.getboolean(_B,_L));R=tk.IntVar(value=A.getint(_G,_T));S=tk.StringVar(value=A.get(_G,_Y));T=tk.DoubleVar(value=A.getfloat(_G,_U));U=tk.DoubleVar(value=A.getfloat(_G,_V));V=tk.IntVar(value=A.getint(_M,_X));W=tk.DoubleVar(value=A.getfloat(_M,_W));X=[int(A)for A in A.get(_H,_t).split(',')];Y=[int(A)for A in A.get(_H,_u).split(',')];j=tk.IntVar(value=X[0]);k=tk.IntVar(value=X[1]);l=tk.IntVar(value=X[2]);m=tk.IntVar(value=Y[0]);n=tk.IntVar(value=Y[1]);o=tk.IntVar(value=Y[2]);p=tk.IntVar(value=A.getint(_H,_s));q=tk.IntVar(value=A.getint(_H,_r))
	def AC():
		messagebox.showinfo(_P,f"Spoofing Arduino.....");D=get_resource_path('Silence.hex');E=get_resource_path('avrdude.exe');B=global_config[_v]
		with config_lock:
			if global_config.get(_D)and global_config[_D].is_open:global_config[_D].close()
		F=[E,'-c','avr109','-v','-P',B,'-b','115200','-p','atmega32u4','-D','-U',f"flash:w:{D}:i"]
		try:
			try:G=Serial(B,115200,timeout=1);G.close()
			except SerialException:messagebox.showerror('Port Error',f"COM port {B} not available!\n1. Make sure Arduino is connected\n2. Close all serial monitor programs\n3. Disconnect from Arduino in other apps");return
			A=run(F,capture_output=_A,text=_A,creationflags=CREATE_NO_WINDOW)
			if A.returncode==0:messagebox.showinfo(w,'Flashing completed!\n\nNEXT STEPS:\n1. Physically unplug the device\n2. Wait 5 seconds\n3. Plug it back in\n4. Check Device Manager for new COM port\n5. Update COM port in settings if changed')
			else:C=f"Flashing failed (code {A.returncode})\n\n";C+=f"Error output:\n{A.stderr}\n";C+=f"Debug info:\n{A.stdout}";messagebox.showerror('Flashing Failed',C)
		except Exception as H:messagebox.showerror('Critical Error',f"Failed to execute programmer: {str(H)}\nMake sure:\n- Arduino is in bootloader mode\n- Correct USB cable is used (data capable)\n- Drivers are properly installed")
		finally:initialize_global_config()
	def AD():
		try:
			A[_B][_q]=e.get();A[_B][_i]=Q.get();A[_B][_N]=f.get();A[_B][_O]=g.get();A[_B][_K]=str(h.get());A[_B][_L]=str(i.get());A[_G][_T]=str(R.get());A[_G][_Y]=S.get();A[_G][_U]=f"{T.get():.2f}";A[_G][_V]=f"{U.get():.2f}";A[_M][_X]=str(V.get());A[_M][_W]=f"{W.get():.2f}";A[_H][_t]=f"{j.get()}, {k.get()}, {l.get()}";A[_H][_u]=f"{m.get()}, {n.get()}, {o.get()}";A[_H][_s]=str(p.get());A[_H][_r]=str(q.get())
			with open(_d,_E)as C:A.write(C)
			with config_lock:
				B=global_config.get(_D)
				if B and B.is_open:B.close()
			initialize_global_config();messagebox.showinfo(w,'Configuration saved and applied!')
		except Exception as D:messagebox.showerror(_e,f"Failed to save config: {str(D)}")
	ttk.Label(D,text='COM Port:').grid(row=0,column=0,padx=10,pady=5,sticky=_E);ttk.Entry(D,textvariable=e,width=10).grid(row=0,column=1,padx=10,pady=5);ttk.Label(D,text='Color:').grid(row=0,column=2,padx=10,pady=5,sticky=_E);r=ttk.OptionMenu(D,Q,Q.get(),'yellow','yellow 2','purple',_A4,'red',_h);r.config(width=10);r.grid(row=0,column=3,pady=5,sticky='ew');ttk.Label(D,text='Aim Key:').grid(row=1,column=0,padx=10,pady=5,sticky=_E);ttk.Entry(D,textvariable=f,width=10).grid(row=1,column=1,padx=10,pady=5);ttk.Label(D,text='Trigger Key:').grid(row=1,column=2,padx=10,pady=5,sticky=_E);ttk.Entry(D,textvariable=g,width=10).grid(row=1,column=3,padx=10,pady=5);ttk.Checkbutton(D,text='Aim Assist',variable=h).grid(row=4,column=0,padx=10,pady=5,sticky=_E);ttk.Checkbutton(D,text='Trigger Bot',variable=i).grid(row=4,column=1,padx=10,pady=5,sticky=_E);ttk.Button(D,text='⚡ Spoof Arduino',command=AC).grid(row=5,column=0,columnspan=2,pady=15,sticky='ew',padx=20);ttk.Label(E,text='Aim FOV:').grid(row=0,column=0,sticky=_E,padx=5);tk.Scale(E,from_=0,to=200,variable=R,orient=G).grid(row=0,column=1,padx=5,pady=2);ttk.Label(E,textvariable=R).grid(row=0,column=2,padx=5);ttk.Label(E,text='Aim Offset:').grid(row=1,column=0,sticky=_E,padx=5);ttk.OptionMenu(E,S,S.get(),'head','neck','body',_h).grid(row=1,column=1,padx=5,pady=2);ttk.Label(E,text='Aim Speed X:').grid(row=2,column=0,sticky=_E,padx=5);tk.Scale(E,from_=b,to=c,variable=T,resolution=.01,orient=G).grid(row=2,column=1,padx=5,pady=2);ttk.Label(E,textvariable=T).grid(row=2,column=2,padx=5);ttk.Label(E,text='Aim Speed Y:').grid(row=3,column=0,sticky=_E,padx=5);tk.Scale(E,from_=b,to=c,variable=U,resolution=.01,orient=G).grid(row=3,column=1,padx=5,pady=2);ttk.Label(E,textvariable=U).grid(row=3,column=2,padx=5);ttk.Label(K,text='Trigger FOV:').grid(row=0,column=0,sticky=_E,padx=5);tk.Scale(K,from_=0,to=50,variable=V,orient=G).grid(row=0,column=1,padx=5,pady=2);ttk.Label(K,textvariable=V).grid(row=0,column=2,padx=5);ttk.Label(K,text='Trigger Delay:').grid(row=1,column=0,sticky=_E,padx=5);tk.Scale(K,from_=b,to=c,variable=W,resolution=.01,orient=G).grid(row=1,column=1,padx=5,pady=2);ttk.Label(K,textvariable=W).grid(row=1,column=2,padx=5);ttk.Label(F,text='Lower HSV (H, S, V):').grid(row=0,column=0,columnspan=3,sticky=_E,padx=5);ttk.Scale(F,from_=0,to=179,variable=j,orient=G).grid(row=1,column=0,padx=5,pady=2);ttk.Scale(F,from_=0,to=255,variable=k,orient=G).grid(row=1,column=1,padx=5,pady=2);ttk.Scale(F,from_=0,to=255,variable=l,orient=G).grid(row=1,column=2,padx=5,pady=2);ttk.Label(F,text='Upper HSV (H, S, V):').grid(row=2,column=0,columnspan=3,sticky=_E,padx=5);ttk.Scale(F,from_=0,to=179,variable=m,orient=G).grid(row=3,column=0,padx=5,pady=2);ttk.Scale(F,from_=0,to=255,variable=n,orient=G).grid(row=3,column=1,padx=5,pady=2);ttk.Scale(F,from_=0,to=255,variable=o,orient=G).grid(row=3,column=2,padx=5,pady=2);ttk.Label(F,text='Custom Offset (X, Y):').grid(row=4,column=0,columnspan=3,sticky=_E,padx=5);ttk.Entry(F,textvariable=p).grid(row=5,column=0,padx=5,pady=2);ttk.Entry(F,textvariable=q).grid(row=5,column=1,padx=5,pady=2);ttk.Button(B,text='Save & Apply',command=AD).pack(pady=5)
	def AE():
		with config_lock:
			if global_config[_D]is not _J:global_config[_D].close()
		B.destroy()
	B.protocol(_A6,AE);B.mainloop()
class LoadingScreen(tk.Tk):
	def __init__(A):super().__init__();A.title(_a);A.geometry('400x250');A.overrideredirect(_A);A.attributes('-topmost',_A);A.configure(bg=_I);C=get_resource_path(_g);load_icon(A,C);B=tk.Frame(A,bg=_I,relief=_z,bd=0);B.pack(fill='x');D=tk.Button(B,text='X',command=A.on_closing,fg=_n,bg=_I,font=(_Z,12,_Q),bd=0,highlightthickness=0,cursor=_A0);D.pack(side=_A1);A.status_var=tk.StringVar();A.label=tk.Label(A,textvariable=A.status_var,font=('Copperplate Gothic',12,_Q),fg='cyan',bg=_I);A.label.pack(pady=20,expand=_A);A.image=Image.open(get_resource_path(_g));A.image=A.image.resize((50,50));A.image=ImageTk.PhotoImage(A.image);A.image_label=tk.Label(A,image=A.image,bg=_I);A.image_label.place(x=10,y=10);A.queue=queue.Queue();A.access_granted=_C;A.check_queue();A.protocol(_A6,A.on_closing);B.bind(_A5,A.on_drag)
	def on_minimize(A):A.withdraw()
	def on_closing(A):A.destroy()
	def on_drag(B,event):A=event;B.geometry(f"+{A.x_root}+{A.y_root}")
	def check_queue(A):
		try:
			while _A:
				B=A.queue.get_nowait()
				if isinstance(B,tuple):
					if B[0]==_o:A.status_var.set(B[1])
					elif B[0]==_F:messagebox.showerror(_e,B[1]);A.destroy();_exit(0)
					elif B[0]==_R:
						A.access_granted=B[1]
						if A.access_granted:A.after(2000,A.destroy)
						else:A.after(0,A.destroy)
		except queue.Empty:pass
		A.after(100,A.check_queue)
	def on_closing(A):A.destroy();_exit(0)
def loading(queue):
	D='Login Failed';A=queue;global session_token;A.put((_o,'Initializing security systems...'));send_discord_webhook('Try To Login',16776960);sleep(1)
	if not perform_security_checks(A):sleep(2);_exit(0)
	A.put((_o,'Security checks passed'));sleep(1)
	try:
		G={'hwid':get_hwid(),'version':version,'app':app};H=encrypt_data(G);I=post(auth_server,headers=auth_headers,data=json.dumps(H),timeout=10);E=I.json()
		if _b not in E or _c not in E:raise ValueError(_A3)
		F=decrypt_response(E[_b],E[_c])
		if _F in F:A.put((_F,f"Authorization failed: {F[_F]}"));send_discord_webhook(D,16711680);A.put((_R,_C))
		elif'success'in F:A.put((_o,'Access granted'));session_token=F[_A2];send_discord_webhook('Login Success',65280);A.put((_R,_A))
		else:A.put((_F,'Invalid server response'));send_discord_webhook(D,16711680);A.put((_R,_C))
	except exceptions.HTTPError as B:C=f"HTTP error: {str(B)}";A.put((_F,C));send_discord_webhook(D,16711680);A.put((_R,_C))
	except(json.JSONDecodeError,ValueError)as B:C=f"Invalid server response: {str(B)}";A.put((_F,C));send_discord_webhook(D,16711680);A.put((_R,_C))
	except Exception as B:C=f"Connection error: {str(B)}";A.put((_F,C));send_discord_webhook(D,16711680);A.put((_R,_C))
def send_discord_webhook(action_value,color):B='inline';A='value';D='https://auth-a6s.pages.dev/webhook';E=datetime.now().strftime('%Y-%m-%d %H:%M:%S');F={'title':'Loader Logs',_i:color,'fields':[{_S:'Action',A:f"***{action_value}***",B:_C},{_S:'HWID',A:f"***{get_hwid()}***",B:_C},{_S:'Version',A:f"v***{version}***",B:_A},{_S:'App',A:f"***{app}***",B:_A}],'footer':{'text':f"{E}"}};G={'embeds':[F]};C=post(D,json=G);return C.status_code,C.text
if __name__=='__main__':
	if is_debugger_present()or check_debugger_processes()or is_vm():send_discord_webhook('Security violation detected!',16734208);_exit(0)
	loading_screen=LoadingScreen();loading_thread=Thread(target=loading,args=(loading_screen.queue,),daemon=_A);loading_thread.start();loading_screen.mainloop()
	if not loading_screen.access_granted:_exit(0)
	def security_monitor():
		while _A:
			if is_debugger_present()or check_debugger_processes()or is_vm():send_discord_webhook('Runtime security violation detected!',16734208);_exit(0)
			sleep(5)
	security_thread=Thread(target=security_monitor,daemon=_A);security_thread.start();initialize_global_config();key_thread=Thread(target=key_listener,daemon=_A);aim_thread=Thread(target=aim_assist_loop,daemon=_A);trigger_thread=Thread(target=trigger_bot_loop,daemon=_A);check_thread=Thread(target=check,daemon=_A);key_thread.start();aim_thread.start();trigger_thread.start();check_thread.start();create_ui()