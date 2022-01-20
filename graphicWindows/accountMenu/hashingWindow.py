
import hashlib

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton

def generate_message_hashing_window(main_screen):

    global message_hashing_window

    global message_to_hash
    global hashed_text
    global varGr

    message_hashing_window = Toplevel(main_screen)

    message_hashing_window.geometry("700x450+380+160")
    message_hashing_window.title("Hashing")
    message_hashing_window.resizable(False,False)

    message_hashing_window.grab_set()
        
    varGr = StringVar()

    Label(message_hashing_window,font=("Calibri", 15), text="Write your message here * ").pack(pady=(15,0))

    
    message_to_hash= Text(message_hashing_window,font=("default",13), width=50, height=3)
    message_to_hash.pack()

    Label(message_hashing_window,font=("Calibri", 15), text="Choose ur hashing method *").pack(pady=(15,10))

    frame1 = Frame(message_hashing_window)
    frame1.pack()

    etiqs = ['SHA1', 'SHA224', 'SHA256', 'SHA384','SHA512','MD5']
    vals = ['SHA1', 'SHA224', 'SHA256', 'SHA384','SHA512','MD5']

    varGr.set(vals[0])
    for i in range(len(vals)):
    
        b = RadioButton(frame1,font=("Calibri", 13),variable=varGr, text=etiqs[i], value=vals[i] , command=hash_text)
        if(i<2):
            b.grid(row=i,column=0,padx=5,pady=5,sticky='w')
        if(i>=2 and i<4):
            b.grid(row=i-2,column=1,padx=5,pady=5,sticky='w')
        if(i>=4):
            b.grid(row=i-4,column=2,padx=5,pady=5,sticky='w')

    Label(message_hashing_window,font=("Calibri", 15), text="Your hashed message : ").pack(pady=(15,10))
    
    hashed_text = Text(message_hashing_window,font=("default",13),fg="red", width=50, height=3)
    hashed_text.pack()

def hash_text():
    method = varGr.get()
    message_data = message_to_hash.get(1.0,END)
    if(message_data):
        if(method == 'SHA1'):
            insert_text(hashlib.sha1(str(message_data).encode()).hexdigest())
        if(method == 'SHA224'):
            insert_text(hashlib.sha224(message_data.encode()).hexdigest())
        if(method == 'SHA256'):
            insert_text(hashlib.sha256(message_data.encode()).hexdigest())
        if(method == 'SHA384'):
            insert_text(hashlib.sha384(message_data.encode()).hexdigest())
        if(method == 'SHA512'):
            insert_text(hashlib.sha512(message_data.encode()).hexdigest())
        if(method == 'MD5'):
            insert_text(hashlib.md5(message_data.encode()).hexdigest())

def insert_text(value):
    hashed_text.delete(1.0,END)
    hashed_text.insert(1.0,value)