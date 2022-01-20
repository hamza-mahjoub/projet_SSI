
from encodings.aliases import aliases
from tkinter import *

from .accountMenu.encodingWindow import generate_message_encoding_window
from .accountMenu.hashingWindow import generate_message_hashing_window
from .accountMenu.symmetricEncryption.symmetricEncryptionWindow import generate_symmetric_encryption_window
from .accountMenu.asymmetricEncryption.asymmetricEncryptionWindow import generate_asymmetric_encryption_window
from .accountMenu.chatRoom.chatRoomRegistrationWindow import generate_chat_room_registration_window
from .accountMenu.crackingWindow import generate_message_cracking_window
# coding a message

def message_encoding_window():
    generate_message_encoding_window(main_screen)

# hashing a message

def message_hashing_window():
    generate_message_hashing_window(main_screen)

# cracking a message

def message_cracking_window():
    generate_message_cracking_window(main_screen)

# symmetric encryption of a message

def symmetric_encryption_window():
    generate_symmetric_encryption_window(main_screen)

# asymmetric encryption of a message

def asymmetric_encryption_window():
    generate_asymmetric_encryption_window(main_screen)

# chat room

def chat_room_window(user):
    generate_chat_room_registration_window(main_screen,user)


def account(user):

    global main_screen

    main_screen = Tk()

    main_screen.geometry("700x600+380+100")
    main_screen.title(user['name']+"_"+user['firstName']+" Account")
    main_screen.resizable(False,False)
    
    Label(text="Welcome "+user['firstName']+", What do you want to do today ?", bg="grey",fg="white", width="300", height="2", font=("Calibri", 13)).pack()
    
    Button(text="Encoding a message",height="3", width="50", command=message_encoding_window).pack(pady=(8,10))
    Button(text="Hashing a message", height="3", width="50", command=message_hashing_window).pack(pady=(15,10))
    Button(text="Crack a message", height="3", width="50", command=message_cracking_window).pack(pady=(15,10))
    Button(text="Symmetric encryption", height="3", width="50", command=symmetric_encryption_window).pack(pady=(15,10))
    Button(text="Asymmetric encryption", height="3", width="50", command=asymmetric_encryption_window).pack(pady=(15,10))
    Button(text="Join the chat room", height="3", width="50", command=lambda:chat_room_window(user)).pack(pady=(15,10))

    main_screen.mainloop()
