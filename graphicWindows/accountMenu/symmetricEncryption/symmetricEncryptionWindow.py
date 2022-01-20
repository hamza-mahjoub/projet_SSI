
import hashlib

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton
from .aes256Window import generate_aes256_window
from .desWindow import generate_des_window

def aes256_window():
    generate_aes256_window(symmetric_encryption_window)

def des_window():
    generate_des_window(symmetric_encryption_window)

def generate_symmetric_encryption_window(main_screen):

    global symmetric_encryption_window

    symmetric_encryption_window = Toplevel(main_screen)

    symmetric_encryption_window.geometry("500x220+480+200")
    symmetric_encryption_window.title("Symmetric Encryption")
    symmetric_encryption_window.resizable(False,False)

    symmetric_encryption_window.grab_set()
    
    Button(symmetric_encryption_window,text="Use AES256", height="3", width="50", command=aes256_window).pack(pady=(25,10))
    Button(symmetric_encryption_window,text="Use DES", height="3", width="50", command=des_window).pack(pady=(15,10))