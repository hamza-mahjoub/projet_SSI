
import base64

from tkinter import *
from tkinter import ttk
from tkinter import Radiobutton as RadioButton
from tkinter import messagebox
from tkinter.filedialog import askopenfilename

def generate_protocole_window(main_screen,type,generate_key,extract_public_key,encrypt_text,decrypt_text,sign_text,verify_signature):

    global protocole_window

    protocole_window = Toplevel(main_screen)

    protocole_window.geometry("700x500+380+180")
    protocole_window.title(type+" protocol")
    protocole_window.resizable(False,False)

    protocole_window = ttk.Notebook(protocole_window)

    tab1 = Frame(protocole_window)
    tab2 = Frame(protocole_window)
    tab3 = Frame(protocole_window)
    tab4 = Frame(protocole_window)
    tab5 = Frame(protocole_window)
    tab6 = Frame(protocole_window)


    protocole_window.add(tab1, text ='Generate '+type+' key')
    protocole_window.add(tab2, text ='Extract '+type+' public key')


    protocole_window.add(tab3, text ='Encrypt')
    protocole_window.add(tab4, text ='Decrypt')
    if type == "RSA":
        protocole_window.add(tab5, text ='Sign')
        protocole_window.add(tab6, text ='Verify Signature')

    protocole_window.pack(expand = 5, fill ="both")

    protocole_window.grab_set()

    global key_location
    global file_location

    if (type == "RSA"):
        key_location="rsaKeys"
        file_location="rsa"
    else:
        key_location="elgamelKeys"
        file_location="elgamel"
    
    ################### generate rsa key ###############################

    global key_file_name
    global generate_key_button
    global key_password

    key_password = StringVar()
    key_file_name = StringVar()

    key_file_name.trace("w",validate_generate_form)
    key_password.trace("w",validate_generate_form)

    Label(tab1,font=("Calibri", 13), text="your "+type+" key will be generated under \n encryption/asymmetricEncryption/"+key_location).pack(pady=(20,0))

    Label(tab1,font=("Calibri", 13), text="Write the password * ").pack(pady=(15,10))

    Entry(tab1,font=("default",13),width=50, textvariable=key_password, show="*").pack()

    Label(tab1,font=("Calibri", 13), text="Write the file name * ").pack(pady=(15,0))

    Entry(tab1,font=("default",13),width=50, textvariable=key_file_name).pack()

    generate_key_button = Button(tab1,text="Generate key", height="3", width="50", command=lambda:generate_key(key_password,key_file_name))
    generate_key_button.pack(pady=(15,10))

    validate_generate_form()

    ################### extract public key ###############################

    global private_key_password
    global private_key
    global submit_extract_button

    global private_key_label    
    global public_key_output_name

    private_key_password = StringVar()
    private_key = StringVar()
    public_key_output_name = StringVar()

    private_key_password.trace("w",validate_extract_form)
    private_key.trace("w",validate_extract_form)
    public_key_output_name.trace("w",validate_extract_form)

    Button(tab2,text="Choose your "+type+" private key", height="3", width="50", command=lambda: choose_file(private_key,private_key_label)).pack(pady=(20,0))
    
    private_key_label = Label(tab2,font=("Calibri", 10), text="Your private key ...")
    private_key_label.pack(pady=(3,10))

    Label(tab2,font=("Calibri", 13), text="Write the password * ").pack(pady=(15,10))
    Entry(tab2,font=("default",13),width=50, textvariable=private_key_password, show="*").pack()

    Label(tab2,font=("Calibri", 13), text="Write the file name * ").pack(pady=(15,0))
    Label(tab2,font=("Calibri", 8),fg="grey", text="files will be located under encryption/asymmetricEncryption/"+file_location).pack(pady=(0,10))
    Entry(tab2,font=("default",13),width=50, textvariable=public_key_output_name).pack()

    submit_extract_button = Button(tab2,text="Submit", height="3", width="50", command=lambda:extract_public_key(private_key_password,private_key,private_key_label,public_key_output_name))
    submit_extract_button.pack(pady=(15,10))

    validate_extract_form()

    ################### encrypt message ###############################

    global message_to_encrypt
    global pub_encryption 
    global output_encrypted_file

    global public_key_label
    global submit_encrypt_button

    output_encrypted_file = StringVar()
    pub_encryption = StringVar()

    output_encrypted_file.trace("w",validate_encrypt_form)
    pub_encryption.trace("w",validate_encrypt_form)
    
    Label(tab3,font=("Calibri", 13), text="Write your message here * ").pack(pady=(20,0))

    message_to_encrypt= Text(tab3,font=("default",13), width=60, height=6)
    message_to_encrypt.pack() 

    Button(tab3,text="Choose your "+type+" public key", height="3", width="50", command=lambda: choose_file(pub_encryption, public_key_label)).pack(pady=(15,0))
    
    public_key_label = Label(tab3,font=("Calibri", 10), text="Your key ...")
    public_key_label.pack(pady=(3,10))

    Label(tab3,font=("Calibri", 13), text="Write the file name * ").pack(pady=(15,0))
    Label(tab3,font=("Calibri", 8),fg="grey", text="files will be located under encryption/asymmetricEncryption/"+file_location).pack(pady=(0,10))

    Entry(tab3,font=("default",13),width=50, textvariable=output_encrypted_file).pack()
    submit_encrypt_button = Button(tab3,text="Submit", height="3", width="50", command=lambda:encrypt_text(output_encrypted_file,pub_encryption,public_key_label,message_to_encrypt))
    submit_encrypt_button.pack(pady=(15,10))

    validate_encrypt_form()

    ################### decrypt message ###############################

    global encrypted_input_file
    global private_key_decryption
    global private_key_password_decryption
    global decrypted_message

    global submit_decrypt_button
    global encrypted_input_file_label
    global private_key_decryption_label     

    encrypted_input_file = StringVar() 
    private_key_decryption = StringVar()
    private_key_password_decryption = StringVar()

    encrypted_input_file.trace("w",validate_decrypt_form)
    private_key_decryption.trace("w",validate_decrypt_form)
    private_key_password_decryption.trace("w",validate_decrypt_form)

    button_frame = Frame(tab4)
    button_frame.pack(pady=(20,0))

    key_frame = Frame(button_frame)
    key_frame.pack(side=LEFT,padx=(15,15))

    input_file = Frame(button_frame)
    input_file.pack(side=LEFT,padx=(15,15))

    Button(key_frame,text="Choose your "+type+" private key", height="3", width="40", command=lambda: choose_file(private_key_decryption, private_key_decryption_label)).pack(pady=(15,0))
    private_key_decryption_label = Label(key_frame,font=("Calibri", 10), text="Your private key ...")
    private_key_decryption_label.pack(pady=(3,10))

    Button(input_file,text="Choose your encrypted File", height="3", width="40", command=lambda: choose_file(encrypted_input_file, encrypted_input_file_label)).pack(pady=(15,0))
    
    encrypted_input_file_label = Label(input_file,font=("Calibri", 10), text="Your encrypted file ...")
    encrypted_input_file_label.pack(pady=(3,10))

    Label(tab4,font=("Calibri", 13), text="Write the password * ").pack(pady=(15,10))
    Entry(tab4,font=("default",13),width=50, textvariable=private_key_password_decryption, show="*").pack()


    submit_decrypt_button = Button(tab4,text="Submit", height="3", width="50", command=lambda:decrypt_text(encrypted_input_file,encrypted_input_file_label,private_key_decryption,private_key_decryption_label,private_key_password_decryption,decrypted_message))
    submit_decrypt_button.pack(pady=(15,10))

    Label(tab4,font=("Calibri", 13), text="your message here * ").pack(pady=(8,0))
    decrypted_message= Text(tab4,font=("default",13), width=60, height=6)
    decrypted_message.pack() 

    validate_decrypt_form()

    if( type == "RSA"):
    ################### sign message ###############################

        global message_to_sign
        global priv_sign 
        global output_signed_file
        global private_key_password_sign

        global priv_sign_label
        global submit_sign_button

        output_signed_file = StringVar()
        priv_sign = StringVar()
        private_key_password_sign = StringVar()

        output_signed_file.trace("w",validate_sign_form)
        priv_sign.trace("w",validate_sign_form)
        private_key_password_sign.trace("w",validate_sign_form)
        
        Label(tab5,font=("Calibri", 13), text="Write your message here * ").pack(pady=(20,0))

        message_to_sign= Text(tab5,font=("default",13), width=60, height=4)
        message_to_sign.pack() 

        Button(tab5,text="Choose your "+type+" private key", height="3", width="50", command=lambda:choose_file(priv_sign, priv_sign_label)).pack(pady=(12,0))
        
        priv_sign_label = Label(tab5,font=("Calibri", 10), text="Your key ...")
        priv_sign_label.pack(pady=(3,10))

        Label(tab5,font=("Calibri", 13), text="Write the password * ").pack(pady=(15,10))
        Entry(tab5,font=("default",13),width=50, textvariable=private_key_password_sign, show="*").pack()

        Label(tab5,font=("Calibri", 13), text="Write the file name * ").pack(pady=(15,0))
        Label(tab5,font=("Calibri", 8),fg="grey", text="files will be located under encryption/asymmetricEncryption/"+file_location).pack(pady=(0,10))
        Entry(tab5,font=("default",13),width=50, textvariable=output_signed_file).pack()

        submit_sign_button = Button(tab5,text="Submit", height="3", width="50", command=lambda:sign_text(private_key_password_sign,output_signed_file,priv_sign,priv_sign_label,message_to_sign))
        submit_sign_button.pack(pady=(15,10))

        validate_sign_form()

        ################### verify signature ###############################

        global input_signed_file
        global public_key_sign
        global verified_signature_message

        global input_signed_file_label
        global public_key_sign_label

        global submit_verify_signature_button

        input_signed_file = StringVar()
        public_key_sign = StringVar()

        input_signed_file.trace("w",validate_verify_signature_form)
        public_key_sign.trace("w",validate_verify_signature_form)

        button_frame_sign = Frame(tab6)
        button_frame_sign.pack(pady=(20,0))

        key_frame_sign = Frame(button_frame_sign)
        key_frame_sign.pack(side=LEFT,padx=(15,15))

        input_file_sign = Frame(button_frame_sign)
        input_file_sign.pack(side=LEFT,padx=(15,15))

        Button(key_frame_sign,text="Choose your "+type+" public key", height="3", width="40", command=lambda:choose_file(public_key_sign, public_key_sign_label)).pack(pady=(15,0))
        public_key_sign_label = Label(key_frame_sign,font=("Calibri", 10), text="Your public key ...")
        public_key_sign_label.pack(pady=(3,10))

        Button(input_file_sign,text="Choose your signed File", height="3", width="40", command=lambda: choose_file(input_signed_file, input_signed_file_label)).pack(pady=(15,0))
        input_signed_file_label = Label(input_file_sign,font=("Calibri", 10), text="Your signed file ...")
        input_signed_file_label.pack(pady=(3,10))

        Label(tab6,font=("Calibri", 13), text="the message to be verified * ").pack(pady=(8,0))
        verified_signature_message= Text(tab6,font=("default",13), width=60, height=6)
        verified_signature_message.pack() 

        submit_verify_signature_button = Button(tab6,text="Submit", height="3", width="50", command=lambda:verify_signature(input_signed_file,input_signed_file_label,public_key_sign,public_key_sign_label,verified_signature_message))
        submit_verify_signature_button.pack(pady=(15,10))

        validate_verify_signature_form()

############################ generate RSA KEY ############################

def validate_generate_form(*args):
    key_data = key_password.get()
    file_data = key_file_name.get()

    if file_data and key_data:
        generate_key_button.config(state='normal')
    else:
        generate_key_button.config(state='disabled')

#################### extract public key #####################################

def validate_extract_form(*args):  
    secret = private_key_password.get()
    priv_key = private_key.get()
    public_key = public_key_output_name.get()

    if secret and priv_key and public_key:
        submit_extract_button.config(state='normal')
    else:
        submit_extract_button.config(state='disabled')

#################### encrypt text #####################################

def validate_encrypt_form(*args):
    output_file = output_encrypted_file.get()
    pub_key = pub_encryption.get()
    message_data = message_to_encrypt.get(1.0,END)

    if pub_key and message_data and output_file:
        submit_encrypt_button.config(state='normal')
    else:
        submit_encrypt_button.config(state='disabled')

#################### decrypt text #####################################

def validate_decrypt_form(*args):
    input_file = encrypted_input_file.get()
    priv_key = private_key_decryption.get()
    secret_key = private_key_password_decryption.get()

    if input_file and priv_key and secret_key:
        submit_decrypt_button.config(state='normal')
    else:
        submit_encrypt_button.config(state='disabled')

#################### sign text #####################################

def validate_sign_form(*args):
    secret_key = private_key_password_sign.get()
    output_file = output_signed_file.get()
    priv_key = priv_sign.get()
    message_data = message_to_sign.get(1.0,END)

    if message_data and priv_key and output_file and secret_key:
        submit_sign_button.config(state='normal')
    else:
        submit_sign_button.config(state='disabled')

#################### verify signature #####################################

def validate_verify_signature_form(*args):
    input_file = input_signed_file.get()
    pub_key = public_key_sign.get()
    message_to_verify = verified_signature_message.get(1.0,END)
    if input_file and pub_key and message_to_verify:
        submit_verify_signature_button.config(state='normal')
    else:
        submit_verify_signature_button.config(state='disabled')

#################### generic #####################################

def choose_file(file_name,field):
    filename = askopenfilename()
    file_name.set(filename)
    field['text'] = "your key : "+filename.rsplit('/',1)[1]
