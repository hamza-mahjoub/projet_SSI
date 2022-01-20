import threading
import socket
import time

from tkinter import *

from .security import *

def connect_server(ip_address, port,name,chat):

    global client
    global alias
    global configuration_thread

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alias = name

    # try:    
    client.connect(('127.0.0.1', 59000))

    receive_thread = threading.Thread(target=client_receive,args=(chat,))
    receive_thread.start()

    return True

    # except:
    #     return False

def initiate_client_recieve(chat,button,ip_address,port,name):
    button.config(state='disabled')
    test = connect_server(ip_address, port, name,chat)
    chat.insert(END, "Listener Configured ... \nExchanging Keys ....")
    time.sleep(10)
    configure_secure_connection()

def client_receive(chat):
    while True:
        # try:
            input_message = client.recv(32767)
            try:
                message = input_message.decode('utf-8')
                if message == "alias?":
                    client.send(alias.encode('utf-8'))
                elif message.split(':')[0] == "server-pub_key":
                    if message.split(':')[1] != alias:
                        user = add_user(message.split(':')[1],message.split(':')[2])
                        chat.insert(END,"\n"+user+"connected !, start chating now !")
                    else:
                        chat.insert(END,"\nEverythig is ready !, You can wait for your friend !")
                elif message.split(':')[0] == "server-remove":
                    print(message)
                    if alias != message.split(':')[1]:
                        name = remove_user(message.split(':')[1])
                        chat.insert(END,"\n"+name+" has quit the server, you are alone :(")
                    else:
                        client.close()
                        break
                elif message != "" and message != "alias?":
                    chat.insert(END,"\n"+message)
                    chat.see("end")
                else:
                    x = 0
                chat.see("end")
            except:
                    if len(input_message) != 0:
                        x,name = find_length(input_message)
                        if name.decode("utf-8") != alias:
                            print("its not mine")
                            decrypted_message = decrypt(input_message[-x:])
                            chat.insert(END,"\n"+name.decode("utf-8")+": "+decrypted_message)
                            chat.see("end")
        # except:
        #     print('Error!')
        #     client.close()
        #     break

def configure_secure_connection():
    pub_key =  get_pub_key()
    output = b''.join([b'pub_key:',pub_key]) # f'pub_key:{message}'
    client.send(output)
    return True

def client_send(message,chat):
    if message:
        if message == "EXIT":
            print("input : ",message)
            client.send(message.encode("utf-8"))
        elif message.split("$")[0] == "/ENCRYPT":
            encrypted_message = encrypt(message.split("$")[1])
            if encrypted_message != "NO_USER":
                output = b'>>>'.join([b'ENCRYPTED',str(len(encrypted_message)).encode("utf-8"),alias.encode("utf-8"),encrypted_message])
                print("Output Encrypted Message :  ",output)
                client.send(output)
                chat.insert(END,"\n"+alias+": "+message.split("$")[1])
                chat.see("end")
        else:
            output = f'{alias}: {message}'
            client.send(output.encode("utf-8"))


