
import base64

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton

def generate_message_encoding_window(main_screen):

    global message_encoding_window

    global message_to_encode
    global encoded_message
    global message_to_decode
    global decoded_message
    global varGr

    global message_entry

    message_encoding_window = Toplevel(main_screen)

    message_encoding_window.geometry("700x400+380+180")
    message_encoding_window.title("Encoding / Decoding")
    message_encoding_window.resizable(False,False)

    message_encoding_window = ttk.Notebook(message_encoding_window)

    tab1 = Frame(message_encoding_window)
    tab2 = Frame(message_encoding_window)

    message_encoding_window.add(tab1, text ='Encode')
    message_encoding_window.add(tab2, text ='Decode')
    message_encoding_window.pack(expand = 5, fill ="both")

    message_encoding_window.grab_set()
    
    varGr = StringVar()
    encoded_message = StringVar()
    message_to_encode = StringVar()
    message_to_decode = StringVar()
    decoded_message = StringVar()

    # encoding tab

    generate_screen(tab1, code_text, "Choose ur encoding method * ", "your encoded message : ",message_to_encode,encoded_message)

    # decode tab

    generate_screen(tab2, decode_text, "Choose ur decoding method * ", "your decoded message : ",message_to_decode,decoded_message)

def generate_screen(tab,method,text1,text2,var1,var2):
    
    Label(tab,font=("Calibri", 13), text="Write your message here * ").pack(pady=(8,0))
    message_entry = Entry(tab,font=("default",13),width=50, textvariable=var1)
    
    message_entry.pack()

    Label(tab,font=("Calibri", 13), text=text1).pack(pady=(15,10))

    frame1 = Frame(tab)
    frame1.pack()
    vals = ['ascii','Base16', 'Base32','b32hex','Base64', 'Base85' ]
    etiqs = ['ascii','Base16', 'Base32','b32hex','Base64', 'Base85' ]
 
    varGr.set(vals[0])
    for i in range(len(vals)):
        b = RadioButton(frame1,font=("Calibri", 13), variable=varGr, text=etiqs[i], value=vals[i], command=method)
        if(i<2):
            b.grid(row=i,column=0,padx=5,pady=5,sticky='w')
        if(i>=2 and i<4):
            b.grid(row=i-2,column=1,padx=5,pady=5,sticky='w')
        if(i>=4):
            b.grid(row=i-4,column=2,padx=5,pady=5,sticky='w')

    Label(tab,font=("Calibri", 15), text=text2).pack(pady=(15,10))

    encoded_message_entry = Entry(tab,fg="red",font=("default",13),width=50, textvariable=var2)
    
    encoded_message_entry.pack()

def code_text():
    method = varGr.get()
    message_data = message_to_encode.get()
    if(message_data):
        if(method == "ascii"):
            encoded_message.set(message_data.encode('ascii','ignore'))
        if(method == "Base16"):
            encoded_message.set(base64.b16encode(message_data.encode()))
        if(method == "Base32"):
            encoded_message.set(base64.b32encode(message_data.encode()))
        if(method == "b32hex"):
            encoded_message.set(base64.b32hexencode(message_data.encode()))
        if(method == "Base64"):
            encoded_message.set(base64.b64encode(message_data.encode()))
        if(method == "Base85"):
            encoded_message.set(base64.b85encode(message_data.encode()))

def decode_text():
    method = varGr.get()
    message_data = message_to_decode.get()
    if(message_data):
        if(method == "ascii"):
            try:
                decoded_message.set(message_data.decode('ascii','ignore'))
            except:
                decoded_message.set("wrong Base ...")
        elif(method == "Base16"):
            try:
                decoded_message.set(base64.b16decode(message_data.encode()))
            except:
                decoded_message.set("wrong Base ...")
        elif(method == "Base32"):
            try:
                decoded_message.set(base64.b32decode(message_data.encode()))
            except:
                decoded_message.set("wrong Base ...")
        elif(method == "b32hex"):
            try:
                decoded_message.set(base64.b32hexdecode(message_data.encode()))
            except:
                decoded_message.set("wrong Base ...")
        elif(method == "Base64"):
            try:
                decoded_message.set(base64.b64decode(message_data.encode()))
            except:
                decoded_message.set("wrong Base ...")
        elif(method == "Base85"):
            try:
                decoded_message.set(base64.b85decode(message_data.encode()))
            except:
                decoded_message.set("wrong Base ...")