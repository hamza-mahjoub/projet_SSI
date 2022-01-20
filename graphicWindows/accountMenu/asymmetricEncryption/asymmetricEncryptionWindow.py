
import hashlib

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton
from .protocolWindow import generate_protocole_window

from .protocols.rsa import *
from .protocols.elgamel import *

def rsa_window():
    generate_protocole_window(asymmetric_encryption_window, "RSA", generate_key, extract_public_key, encrypt_text, decrypt_text, sign_text, verify_signature)

def elgamel_window():
    generate_protocole_window(asymmetric_encryption_window, "ElGamel", elgamel_generate_key, elgamel_extract_public_key, elgamel_encrypt_text, elgamel_decrypt_text, elgamel_sign_text, elgamel_verify_signature)


def generate_asymmetric_encryption_window(main_screen):

    global asymmetric_encryption_window

    asymmetric_encryption_window = Toplevel(main_screen)

    asymmetric_encryption_window.geometry("500x220+480+200")
    asymmetric_encryption_window.title("Symmetric Encryption")
    asymmetric_encryption_window.resizable(False,False)

    asymmetric_encryption_window.grab_set()
    
    Button(asymmetric_encryption_window,text="Use RSA", height="3", width="50", command=rsa_window).pack(pady=(25,10))
    Button(asymmetric_encryption_window,text="Use ElGAMEL", height="3", width="50", command=elgamel_window).pack(pady=(15,10))