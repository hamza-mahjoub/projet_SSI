
import base64

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_aes256_window(main_screen):

    global aes256_window

    global key
    global file_name
    global encrypted_file_name
    global message_to_encrypt
    global decrypted_message

    global file_label

    global submit_encrypt_button
    global submit_decrypt_button

    aes256_window = Toplevel(main_screen)

    aes256_window.geometry("700x500+380+180")
    aes256_window.title("AES256 protocol")
    aes256_window.resizable(False,False)

    aes256_window = ttk.Notebook(aes256_window)

    tab1 = Frame(aes256_window)
    tab2 = Frame(aes256_window)

    aes256_window.add(tab1, text ='Encrypt')
    aes256_window.add(tab2, text ='Decrypt')
    aes256_window.pack(expand = 5, fill ="both")

    aes256_window.grab_set()
    
    # main_screen.destroy()

    key = StringVar()
    file_name = StringVar()
    encrypted_file_name = StringVar()

    key.trace("w",validate_encrypt_form)
    file_name.trace("w",validate_encrypt_form)

    encrypted_file_name.trace("w",validate_decrypt_form)
    key.trace("w",validate_decrypt_form)


    # encrypting tab

    Label(tab1,font=("Calibri", 13), text="Write your message here * ").pack(pady=(8,0))

    message_to_encrypt= Text(tab1,font=("default",13), width=50, height=6)
    message_to_encrypt.pack() 

    Label(tab1,font=("Calibri", 13), text="Write the secret key * ").pack(pady=(15,10))

    Entry(tab1,font=("default",13),width=50, textvariable=key, show="*").pack()

    Label(tab1,font=("Calibri", 13), text="Write the file name * ").pack(pady=(15,0))
    Label(tab1,font=("Calibri", 8),fg="grey", text="files will be located under encryption/symmetricEncryption/aes256").pack(pady=(0,10))

    Entry(tab1,font=("default",13),width=50, textvariable=file_name).pack()

    submit_encrypt_button = Button(tab1,text="Encrypt", height="3", width="50", command=encrypt_text)
    submit_encrypt_button.pack(pady=(15,10))

    validate_encrypt_form()

    # decrypting tab    

    Button(tab2,text="Choose ur file", height="3", width="50", command=choose_encrypted_file).pack(pady=(15,0))

    file_label = Label(tab2,font=("Calibri", 10), text="Your file ...")
    file_label.pack(pady=(3,10))

    Label(tab2,font=("Calibri", 13), text="Write the secret key * ").pack(pady=(15,10))

    Entry(tab2,font=("default",13),width=50, textvariable=key, show="*").pack()

    submit_decrypt_button = Button(tab2,text="Decrypt", height="3", width="50", command=decrypt_text)
    submit_decrypt_button.pack(pady=(15,10))

    decrypted_message= Text(tab2,font=("default",13), width=50, height=7)
    decrypted_message.pack() 
    validate_decrypt_form()

def validate_encrypt_form(*args):
    message_encrypt_data = message_to_encrypt.get(1.0,END)
    key_data = key.get()
    file_data = file_name.get()

    if message_encrypt_data and key_data and file_data:
        submit_encrypt_button.config(state='normal')
    else:
        submit_encrypt_button.config(state='disabled')

def validate_decrypt_form(*args):

    key_data = key.get()
    file_data = encrypted_file_name.get()

    if encrypted_file_name and key_data:
        submit_decrypt_button.config(state='normal')
    else:
        submit_decrypt_button.config(state='disabled')


def encrypt_text():
    message_data = message_to_encrypt.get(1.0,END)
    key_data = key.get()
    file_data = file_name.get()

    if message_data and key_data and file_data:
        try:
            secret_key = pad_key(key_data)

            cipher = AES.new(secret_key.encode("utf8"), AES.MODE_EAX)

            ciphertext, tag = cipher.encrypt_and_digest(message_data.encode("utf8"))

            file_out = open("encryption/symmetricEncryption/aes256/"+file_data+".enc", "wb")
            [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            file_out.close()

            key.set('')
            insert_text(message_to_encrypt, '')
            file_name.set('')

            messagebox.showinfo(title="success", message=file_data+" encrypted successfully !")
        except:
            messagebox.showerror(title="error", message="Something went wrong ... ")
    else:

        messagebox.showerror(title="error", message="All fields must have a value")


def choose_encrypted_file():
    filename = askopenfilename()
    encrypted_file_name.set(filename)
    file_label['text'] = "your file : "+encrypted_file_name.get().rsplit('/',1)[1]

def decrypt_text():
    key_data = key.get()
    file_data = encrypted_file_name.get()
    if file_data and key_data:
            try:
                secret_key = pad_key(key_data)

                file_in = open(file_data, "rb")
                nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

                cipher = AES.new(secret_key.encode("utf8"), AES.MODE_EAX, nonce)

                data = cipher.decrypt_and_verify(ciphertext, tag)

                messagebox.showinfo(title="success", message=file_data.rsplit('/',1)[1]+" decrypted successfully !")

                insert_text(decrypted_message, data.decode())
                key.set('')
                encrypted_file_name.set('')
                file_label['text'] = "your file : ..."

            except:
                messagebox.showerror(title="error", message="Something went wrong ... ")
    else:

        messagebox.showerror(title="error", message="Key or file missing !  ")

def pad_key(key):
        while len(key) % 16 != 0:
            key += ' '
        return key

def insert_text(field,value):
    field.delete(1.0,END)
    field.insert(1.0,value)