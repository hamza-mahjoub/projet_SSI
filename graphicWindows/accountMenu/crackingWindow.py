
import hashlib

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton
from tkinter import messagebox
from tkinter.filedialog import askopenfilename

def generate_message_cracking_window(main_screen):

    global message_cracking_window

    global dictionary
    global dictionary_label
    global crack_button
    global message_to_crack
    global cracked_message
    global varGr

    message_cracking_window = Toplevel(main_screen)

    message_cracking_window.geometry("700x400+380+180")
    message_cracking_window.title("Cracking")
    message_cracking_window.resizable(False,False)

    message_cracking_window.grab_set()
        
    varGr = StringVar()
    dictionary = StringVar()

    dictionary.trace("w",validate_cracking_form)

    Label(message_cracking_window,font=("Calibri", 12), text="Write your hashed here * ").pack(pady=(15,0))

    message_to_crack= Text(message_cracking_window,font=("default",13), width=60, height=3)
    message_to_crack.pack()

    fieldset = LabelFrame(message_cracking_window, text="Function and file configuration")
    fieldset.pack(fill="both", expand="no",pady=(20,0))  

    button_frame = Frame(fieldset)
    button_frame.pack(side=LEFT,pady=(15,0),padx=(15,0))

    Label(button_frame,font=("Calibri", 10), text="Choose ur cracking method *").pack()

    frame1 = Frame(button_frame)
    frame1.pack()

    etiqs = ['SHA1', 'SHA224', 'SHA256', 'SHA384','SHA512','MD5']
    vals = ['SHA1', 'SHA224', 'SHA256', 'SHA384','SHA512','MD5']

    varGr.set(vals[0])
    for i in range(len(vals)):
    
        b = RadioButton(frame1,font=("Calibri", 10),variable=varGr, text=etiqs[i], value=vals[i])
        if(i<2):
            b.grid(row=i,column=0,padx=5,pady=5,sticky='w')
        if(i>=2 and i<4):
            b.grid(row=i-2,column=1,padx=5,pady=5,sticky='w')
        if(i>=4):
            b.grid(row=i-4,column=2,padx=5,pady=5,sticky='w')


    Button(fieldset,text="Choose your dictionary", height="3", width="30", command=choose_file).pack(pady=(15,0))
    dictionary_label = Label(fieldset,font=("Calibri", 10), text="Your chosen dictionary: ")
    dictionary_label.pack()

    crack_button = Button(message_cracking_window,text="Crack", height="2", width="30", command=crack_message)
    crack_button.pack(pady=(15,0))

    Label(message_cracking_window,font=("Calibri", 13), text="Your hashed message : ").pack(pady=(10,0))
    cracked_message = Text(message_cracking_window,font=("default",13),fg="red", width=60, height=2)
    cracked_message.pack()

    validate_cracking_form()

def validate_cracking_form(*args):
    dictionary_data = dictionary.get()
    message_to_crack_data = message_to_crack.get(1.0,END)

    if dictionary_data and len(message_to_crack_data) != 0:
        crack_button.config(state='normal')
    else:
        crack_button.config(state='disabled')

def choose_file():
    filename = askopenfilename()
    dictionary.set(filename)
    dictionary_label['text'] = "your dictionary : "+filename.rsplit('/',1)[1]

def crack_message():
    method = varGr.get()
    message_data = message_to_crack.get(1.0,END)
    file_data = dictionary.get()
    if file_data and message_data and method :
        file_in = open(file_data,"rb")
        is_found = False
        if(method == 'SHA1'):
            for email in file_in:
                h = hashlib.sha1(email).hexdigest()
                if [ord(c) for c in h] == [ord(g) for g in message_data[0:len(message_data)-1]]:
                    insert_text(email)
                    is_found = True
                    break
            if is_found == False:
                insert_text("Not found, Try another dictionary ! ")
        if(method == 'SHA224'):
            for email in file_in:
                h = hashlib.sha224(email).hexdigest()
                if [ord(c) for c in h] == [ord(g) for g in message_data[0:len(message_data)-1]]:
                    insert_text(email)
                    is_found = True
                    break
            if is_found == False:
                insert_text("Not found, Try another dictionary ! ")
        if(method == 'SHA256'):
            for email in file_in:
                h = hashlib.sha256(email).hexdigest()
                if [ord(c) for c in h] == [ord(g) for g in message_data[0:len(message_data)-1]]:
                    insert_text(email)
                    is_found = True
                    break
            if is_found == False:
                insert_text("Not found, Try another dictionary ! ")
        if(method == 'SHA384'):
            for email in file_in:
                h = hashlib.sha384(email).hexdigest()
                if [ord(c) for c in h] == [ord(g) for g in message_data[0:len(message_data)-1]]:
                    insert_text(email)
                    is_found = True
                    break
            if is_found == False:
                insert_text("Not found, Try another dictionary ! ")
        if(method == 'SHA512'):
            for email in file_in:
                h = hashlib.sha512(email).hexdigest()
                if [ord(c) for c in h] == [ord(g) for g in message_data[0:len(message_data)-1]]:
                    insert_text(email)
                    is_found = True
                    break
            if is_found == False:
                insert_text("Not found, Try another dictionary ! ")
        if(method == 'MD5'):
            for email in file_in:
                h = hashlib.md5(email).hexdigest()
                if [ord(c) for c in h] == [ord(g) for g in message_data[0:len(message_data)-1]]:
                    insert_text(email)
                    is_found = True
                    break
            if is_found == False:
                insert_text("Not found, Try another dictionary ! ")


def insert_text(value):
    cracked_message.delete(1.0,END)
    cracked_message.insert(1.0,value)