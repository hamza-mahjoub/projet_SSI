
import socket
import select

import re

from tkinter import *

from .client import connect_server,client_send,initiate_client_recieve,configure_secure_connection


def generate_chat_room_window(main_screen,app_user,ip_address,port,name):
    

    global main_screen_menu
    global user 
    global alias

    main_screen_menu = main_screen
    user = app_user
    alias = name

    global chat_room_window

    chat_room_window = Toplevel(main_screen)

    chat_room_window.geometry("700x450+380+160")
    chat_room_window.title("Chat Room")
    chat_room_window.resizable(False,False)

    chat_room_window.grab_set()



    global chat
    global isConnected 
    
    global chat_box_entry

    global send_button
    global exit_button
    global ecrypt_button
    global connect_button

    chat_box_entry = StringVar()
    isConnected = StringVar()

    isConnected.set("FALSE")

    chat_box_entry.trace("w",validate_send_form)
    isConnected.trace("w",validate_exit)

    Label(chat_room_window,font=("Calibri", 13), text=alias).pack(pady=(10,0))

    chat= Text(chat_room_window,font=("default",10), width=90, height=16)
    chat.pack(pady=(10,20))

    frame = Frame(chat_room_window)
    frame.pack(padx=(10,20))

    Entry(frame,font=("default",13),width=60, textvariable=chat_box_entry).pack(side=LEFT,padx=(10,10))

    send_button = Button(frame,text="Send", height="2", width="10", command= send_message)
    send_button.pack()

    button_frame = Frame(chat_room_window)
    button_frame.pack(padx=(10,20))

    exit_button = Button(button_frame,text="Exit", height="2", width="10", command= exit_chat)
    exit_button.pack(side=LEFT)

    connect_button = Button(button_frame,text="Connect", height="2", width="20", command= lambda:initiate_listener(ip_address,port))
    connect_button.pack(side =LEFT)

    ecrypt_button = Button(button_frame,text="Encrypt and send", height="2", width="20", command= encrypt_message)
    ecrypt_button.pack()

    validate_send_form()
    validate_exit()

#################### validators ############################ 

def validate_send_form(*args):
    message = chat_box_entry.get()
    if message:
        send_button.config(state='normal')
        ecrypt_button.config(state='normal')
    else:
        send_button.config(state='disabled')
        ecrypt_button.config(state='disabled')

    if(isConnected.get() ==  "TRUE"):
        exit_button.config(state='normal')

def validate_exit(*args):
    if isConnected == "TRUE":
        exit_button.config(state='normal')
    else:
        exit_button.config(state='disabled')

def initiate_listener(ip_address,port):
    chat.insert(END, "Configuring Listener ... \n")
    initiate_client_recieve(chat,connect_button,ip_address,port,alias)
    isConnected.set("TRUE")
    
def exit_chat():
    client_send("EXIT",chat)
    chat_room_window.destroy()

def encrypt_message():
    message = chat_box_entry.get()
    if message and isConnected.get() == "TRUE":
        client_send("/ENCRYPT$"+message,chat)
        chat_box_entry.set("")

def send_message():
    message = chat_box_entry.get()
    if message and isConnected.get() == "TRUE":
        client_send(message,chat)
        chat_box_entry.set("")


