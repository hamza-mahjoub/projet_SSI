
import base64

from tkinter import *
from tkinter import messagebox

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import Crypto.Util.number as num

import hashlib
import random
from math import pow


############################ generate ElGamel KEY ############################

#To find gcd of two numbers
def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b;
    else:
        return gcd(b, a % b)
 
# Generating large random numbers
def gen_key(q):
 
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q)
 
    return key

# Modular exponentiation
def power(a, b, c):
    x = 1
    y = a
 
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c;
        y = (y * y) % c
        b = int(b / 2)
 
    return x % c

############################ generate ElGamel KEY ############################

def elgamel_generate_key(key_password,key_file_name):
    key_data = key_password.get()
    file_data = key_file_name.get()
    if file_data and key_data:
        # try:

            q = random.randint(pow(10, 20), pow(10, 50))

            g = random.randint(2, q)

            key = gen_key(q)# Private key for receiver

            secret_key = pad_key(key_data)

            cipher = DES.new(secret_key.encode("utf8"), DES.MODE_EAX)

            message_data = str(q)+"$"+str(g)+"$"+str(key)

            ciphertext, tag = cipher.encrypt_and_digest(message_data.encode("utf8"))

            file_out = open("encryption/asymmetricEncryption/elgamelKeys/"+file_data+".enc", "wb")
            [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            file_out.close()

            key_password.set('')
            key_file_name.set('')

            messagebox.showinfo(title="success", message=file_data+" generated successfully !")

    #     except:
    #         messagebox.showerror(title="error", message="something went wrong !...")
    # else:
    #     messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### extract public key #####################################

def elgamel_extract_public_key(private_key_password,private_key,private_key_label,public_key_output_name):
    secret = private_key_password.get()
    priv_key = private_key.get()
    public_key = public_key_output_name.get()

    if secret and priv_key and public_key:
        try:
            secret_key = pad_key(secret)

            file_in = open(priv_key, "rb")
            nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 8, -1) ]

            cipher = DES.new(secret_key.encode("utf8"), DES.MODE_EAX, nonce)

            data = cipher.decrypt_and_verify(ciphertext, tag)

            decoded_data = data.decode()

            q = int(decoded_data.split("$")[0])

            g = int(decoded_data.split("$")[1])

            key = int(decoded_data.split("$")[2])

            h = power(g, key, q)

            message_data = str(q)+"$"+str(g)+"$"+str(h)

            file_out = open("encryption/asymmetricEncryption/elgamelKeys/"+public_key+".pem", "wb")
            file_out.write(message_data.encode("utf-8"))
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

def elgamel_encrypt_text(output_encrypted_file,pub_encryption,public_key_label,message_to_encrypt):
    output_file = output_encrypted_file.get()
    pub_key = pub_encryption.get()
    message_data = message_to_encrypt.get(1.0,END)

    if pub_key and message_data and output_file:
        try:
            file_out = open("encryption/asymmetricEncryption/elgamel/"+output_file+".bin", "wb")

            public_key = open(pub_key,"rb").read().decode()

            q = int(public_key.split("$")[0])
            g = int(public_key.split("$")[1])
            h = int(public_key.split("$")[2])
            
            ct=[]
            k=gen_key(q)
            s=power(h,k,q)
            p=power(g,k,q)

            for i in range(0,len(message_data)):
                ct.append(message_data[i])

            for i in range(0,len(ct)):
                ct[i]=s*ord(ct[i])
            
            encrypted_message = ''
            for i in range(0,len(ct)):
                encrypted_message += str(ct[i])+','

            encrypted_message += str(p)

            file_out.write(encrypted_message.encode("utf-8"))
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

def elgamel_decrypt_text(encrypted_input_file,encrypted_input_file_label,private_key_decryption,private_key_decryption_label,private_key_password_decryption,decrypted_message):
    input_file = encrypted_input_file.get()
    priv_key = private_key_decryption.get()
    secret_key = private_key_password_decryption.get()

    if input_file and priv_key and secret_key:
        try:
            # private key

            secret = pad_key(secret_key)

            file_in = open(priv_key, "rb")

            nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 8, -1) ]
            cipher = DES.new(secret.encode("utf8"), DES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            decoded_data = data.decode()

            # encrypted data

            file_in = open(input_file, "rb")
            encrypted_data = file_in.read().decode().split(',')
            
            # decryption

            q = int(decoded_data.split("$")[0])
            key = int(decoded_data.split("$")[2])
            
            ct=[]
            p=int(encrypted_data[len(encrypted_data)-1])
            for i in range(len(encrypted_data)):
                if(i != len(encrypted_data)-1):
                    ct.append(int(encrypted_data[i]))
        
            pt=[]
            h=power(p,key,q)
            for i in range(0,len(ct)):
                pt.append(chr(int(ct[i]/h)))

            message=''
            for i in range(len(pt)):
                message += pt[i]

            insert_text(decrypted_message, message)

            clear_file(encrypted_input_file, encrypted_input_file_label)
            clear_file(private_key_decryption,private_key_decryption_label)
            private_key_password_decryption.set('')

            messagebox.showinfo(title="success", message=input_file.rsplit('/',1)[1]+" decrypted successfully !")
        except:
            messagebox.showerror(title="error", message="something went wrong !...")
    else:
        messagebox.showerror(title="error", message="All fields must have a value ! ")


#################### Problem   #####################################

#################### sign text #####################################

def elgamel_sign_text(private_key_password_sign,output_signed_file,priv_sign,priv_sign_label,message_to_sign):
    secret_key = private_key_password_sign.get()
    output_file = output_signed_file.get()
    priv_key = priv_sign.get()
    message_data = message_to_sign.get(1.0,END)

    if message_data and priv_key and output_file and secret_key:
        try:
            file_out = open("encryption/asymmetricEncryption/elgamel/"+output_file+".bin", "wb")

            # private key

            secret = pad_key(secret_key)

            file_in = open(priv_key, "rb")

            nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 8, -1) ]
            cipher = DES.new(secret.encode("utf8"), DES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            decoded_data = data.decode()

            q = int(decoded_data.split("$")[0])
            g = int(decoded_data.split("$")[1])
            key = int(decoded_data.split("$")[2])

            k = gen_key(q)

            ##########################

            hashed = hashlib.sha256(message_data.encode('utf-8')).hexdigest()
            mes = int(hashed,16)

            R = power(g, k, q)
            t=num.inverse(k,q)
            S=t*(mes-R*key)%(q)

            signature = str(R)+"$"+str(S)
            print("R ",R)
            print("S ",S)
            file_out.write(signature.encode("utf-8"))
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

def elgamel_verify_signature(input_signed_file,input_signed_file_label,public_key_sign,public_key_sign_label,verified_signature_message):
    input_file = input_signed_file.get()
    pub_key = public_key_sign.get()
    message_to_verify = verified_signature_message.get(1.0,END)

    if input_file and pub_key and message_to_verify:
        # try:
            
            signature = open(input_file,"rb").read().decode().split("$")

            R = int(signature[0])
            S = int(signature[1])

            print("R ",R)
            print("S ",S)

            public_key = open(pub_key,"rb").read().decode().split("$")

            q = int(public_key[0])
            g = int(public_key[1])
            h = int(public_key[2])

            if (R>q) or (S>(q-1)) or (num.GCD(g,(q-1))!=1) :
                messagebox.showerror(title="error", message="Wrong parameters !..., The signature is not valid.") 
            else:     

                hashed = hashlib.sha256(message_to_verify.encode('utf-8')).hexdigest()
                mes = int(hashed,16)

                D1=power(g,mes,q) #D1=g^m mod p
                D2=(power(h,R,q)*power(R,S,q))%q #D2=y^R*R^S(mod p)

                print(D1)
                print(D2)
                
                if (D1==D2):
                    messagebox.showinfo(title="success", message=input_file.rsplit('/',1)[1]+" verified successfully ! \n The signature is valid.")
                else:
                    messagebox.showerror(title="error", message="Wrong parameters !..., The signature is not valid.") 

                clear_file(input_signed_file, input_signed_file_label)
                clear_file(public_key_sign, public_key_sign_label)
                verified_signature_message.delete(1.0,END)
    #     except:
    #         messagebox.showerror(title="error", message="something went wrong !..., The signature is not valid.")
    # else:
    #     messagebox.showerror(title="error", message="All fields must have a value ! ")

#################### generic #####################################

def insert_text(field,value):
    field.delete(1.0,END)
    field.insert(1.0,value)

def clear_file(file_name,field):
    file_name.set('')
    field['text'] = "...."

def pad_key(key):
        while len(key) % 8 != 0:
            key += ' '
        return key