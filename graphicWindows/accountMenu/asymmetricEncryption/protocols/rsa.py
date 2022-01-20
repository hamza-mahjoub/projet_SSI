
import base64

from tkinter import *
from tkinter import messagebox

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

############################ generate RSA KEY ############################

def generate_key(key_password,key_file_name):
    key_data = key_password.get()
    file_data = key_file_name.get()
    if file_data and key_data:
        try:
            key = RSA.generate(2048)

            encrypted_key = key.export_key(passphrase=key_data, pkcs=8, protection="scryptAndAES128-CBC")

            file_out = open("encryption/asymmetricEncryption/rsaKeys/"+file_data+".pem", "wb")
            file_out.write(encrypted_key)
            file_out.close()

            key_password.set('')
            key_file_name.set('')

            messagebox.showinfo(title="success", message=file_data+" generated successfully !")

        except:
            messagebox.showerror(title="error", message="something went wrong !...")
    else:
        messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### extract public key #####################################

def extract_public_key(private_key_password,private_key,private_key_label,public_key_output_name):
    secret = private_key_password.get()
    priv_key = private_key.get()
    public_key = public_key_output_name.get()

    if secret and priv_key and public_key:
        try:
            encoded_key = open(priv_key, "rb").read()
            key = RSA.import_key(encoded_key, passphrase=secret)

            file_out = open("encryption/asymmetricEncryption/rsaKeys/"+public_key+".pem", "wb")
            file_out.write(key.publickey().export_key())
            file_out.close()

            messagebox.showinfo(title="success", message=public_key+" generated successfully !")

            private_key_password.set('')
            clear_file(private_key, private_key_label)
            public_key_output_name.set('')
        except:
            messagebox.showerror(title="error", message="something went wrong !...")
    else:
        messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### encrypt text #####################################

def encrypt_text(output_encrypted_file,pub_encryption,public_key_label,message_to_encrypt):
    output_file = output_encrypted_file.get()
    pub_key = pub_encryption.get()
    message_data = message_to_encrypt.get(1.0,END)

    if pub_key and message_data and output_file:
        try:
            file_out = open("encryption/asymmetricEncryption/rsa/"+output_file+".bin", "wb")

            recipient_key = RSA.import_key(open(pub_key).read())
            session_key = get_random_bytes(16)

            # Encrypt the session key with the public RSA key
            cipher = PKCS1_OAEP.new(recipient_key)
            enc_session_key = cipher.encrypt(session_key)

            # Encrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message_data.encode("utf-8"))
            [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
            file_out.close()

            output_encrypted_file.set('')
            clear_file(pub_encryption, public_key_label)
            message_to_encrypt.delete(1.0,END)

            messagebox.showinfo(title="success", message=output_file+" encrypted successfully !")
        except:
            messagebox.showerror(title="error", message="something went wrong !...")
    else:
        messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### decrypt text #####################################

def decrypt_text(encrypted_input_file,encrypted_input_file_label,private_key_decryption,private_key_decryption_label,private_key_password_decryption,decrypted_message):
    input_file = encrypted_input_file.get()
    priv_key = private_key_decryption.get()
    secret_key = private_key_password_decryption.get()

    if input_file and priv_key and secret_key:
        # try:

            file_in = open(input_file, "rb")

            encoded_key = open(priv_key, "rb").read()
            private_key = RSA.import_key(encoded_key, passphrase=secret_key)

            enc_session_key, nonce, tag, ciphertext = \
            [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

            # Decrypt the session key with the private RSA key
            cipher = PKCS1_OAEP.new(private_key)
            session_key = cipher.decrypt(enc_session_key)

            # Decrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            insert_text(decrypted_message, data.decode("utf-8"))

            clear_file(encrypted_input_file, encrypted_input_file_label)
            clear_file(private_key_decryption,private_key_decryption_label)
            private_key_password_decryption.set('')

    #         messagebox.showinfo(title="success", message=input_file.rsplit('/',1)[1]+" decrypted successfully !")
    #     except:
    #         messagebox.showerror(title="error", message="something went wrong !...")
    # else:
    #     messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### sign text #####################################

def sign_text(private_key_password_sign,output_signed_file,priv_sign,priv_sign_label,message_to_sign):
    secret_key = private_key_password_sign.get()
    output_file = output_signed_file.get()
    priv_key = priv_sign.get()
    message_data = message_to_sign.get(1.0,END)

    if message_data and priv_key and output_file and secret_key:
        try:
            file_out = open("encryption/asymmetricEncryption/rsa/"+output_file+".bin", "wb")

            encoded_key = open(priv_key, "rb").read()
            key = RSA.import_key(encoded_key, passphrase=secret_key)

            h = SHA256.new(message_data.encode("utf-8"))
            signature = pkcs1_15.new(key).sign(h)

            file_out.write(signature)
            file_out.close()

            private_key_password_sign.set('')
            output_signed_file.set('')
            clear_file(priv_sign, priv_sign_label)
            message_to_sign.delete(1.0,END)

            messagebox.showinfo(title="success", message=output_file+" signed successfully !")
        except:
            messagebox.showerror(title="error", message="something went wrong !...")
    else:
        messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### verify signature #####################################

def verify_signature(input_signed_file,input_signed_file_label,public_key_sign,public_key_sign_label,verified_signature_message):
    input_file = input_signed_file.get()
    pub_key = public_key_sign.get()
    message_to_verify = verified_signature_message.get(1.0,END)

    if input_file and pub_key and message_to_verify:
        try:
            
            signature = open(input_file,"rb").read()
            key = RSA.import_key(open(pub_key).read())
            h = SHA256.new(message_to_verify.encode("utf-8"))
    
            pkcs1_15.new(key).verify(h, signature)

            clear_file(input_signed_file, input_signed_file_label)
            clear_file(public_key_sign, public_key_sign_label)
            verified_signature_message.delete(1.0,END)

            messagebox.showinfo(title="success", message=input_file.rsplit('/',1)[1]+" verified successfully ! \n The signature is valid.")

        except:
            messagebox.showerror(title="error", message="something went wrong !..., The signature is not valid.")
    else:
        messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### generic #####################################

def insert_text(field,value):
    field.delete(1.0,END)
    field.insert(1.0,value)

def clear_file(file_name,field):
    file_name.set('')
    field['text'] = "...."