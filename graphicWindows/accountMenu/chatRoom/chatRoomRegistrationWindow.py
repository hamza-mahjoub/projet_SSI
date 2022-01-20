
import socket
import select

import re

from tkinter import *
from tkinter import messagebox
from tkinter.filedialog import askopenfilename

from .chatRoomWindow import generate_chat_room_window
from .client import connect_server,configure_secure_connection
from .security import configure_keys

def generate_chat_room_registration_window(main_screen,app_user):


    global main_screen_menu
    global user 

    main_screen_menu = main_screen
    user = app_user

    global chat_room_register_window

    global ip_address
    global port
    global private_key_password
    global private_key
    
    global ip_address_entry
    global port_entry

    global private_key_label
    global ip_address_error_label
    global port_error_label

    global submit_register_button

    chat_room_register_window = Toplevel(main_screen)

    chat_room_register_window.geometry("700x450+380+160")
    chat_room_register_window.title("Server registration")
    chat_room_register_window.resizable(False,False)

    chat_room_register_window.grab_set()

    ip_address = StringVar()
    port = StringVar()
    private_key_password= StringVar()
    private_key = StringVar()

    ip_address.set("127.0.0.1")
    port.set("59000")
    ip_address.trace("w",validate_server_register_form)
    port.trace("w",validate_server_register_form)
    private_key_password.trace("w",validate_server_register_form)
    private_key.trace("w",validate_server_register_form)

    Label(chat_room_register_window,font=("Calibri", 13), text="Your Alias will be : "+user["name"]+"_"+user["firstName"]+"("+user["email"]+")").pack(pady=(15,10))


    Label(chat_room_register_window,font=("Calibri", 13), text="Write the server Ip address key * ").pack(pady=(15,10))

    # ip address validator
    ip_address_entry = Entry(chat_room_register_window, font=("default",13),width=50, textvariable=ip_address)
    vacmd = (chat_room_register_window.register(validate_address), '%P')
    ivacmd = (chat_room_register_window.register(on_invalid_address))
    ip_address_entry.config(validate='focusout',validatecommand=vacmd, invalidcommand=ivacmd)
    ip_address_entry.pack()
    ip_address_error_label = Label(chat_room_register_window,fg="red")
    ip_address_error_label.pack()

    Label(chat_room_register_window,font=("Calibri", 13), text="Write the server port * ").pack(pady=(0,0))

    # port validator
    port_entry = Entry(chat_room_register_window, font=("default",13),width=50, textvariable=port)
    vpcmd = (chat_room_register_window.register(validate_port), '%P')
    ivpcmd = (chat_room_register_window.register(on_invalid_port))
    port_entry.config(validate='focusout',validatecommand=vpcmd, invalidcommand=ivpcmd)
    port_entry.pack()
    port_error_label = Label(chat_room_register_window,fg="red")
    port_error_label.pack()

    fieldset = LabelFrame(chat_room_register_window, text="RSA key configuration")
    fieldset.pack(fill="both", expand="yes")  

    button_frame = Frame(fieldset)
    button_frame.pack(side=LEFT)

    Button(button_frame,text="Choose your RSA private key", height="3", width="30", command=lambda: choose_file(private_key,private_key_label)).pack(padx=(20,20),pady=(20,0))
    
    private_key_label = Label(button_frame,font=("Calibri", 10), text="Your private key ...")
    private_key_label.pack(pady=(3,10))

    Label(fieldset,font=("Calibri", 13), text="Write the password * ").pack(pady=(20,0))
    Entry(fieldset,font=("default",13),width=50, textvariable=private_key_password, show="*").pack(padx=(20,20))

    submit_register_button = Button(chat_room_register_window,text="Register to server", height="3", width="50", command=register)
    submit_register_button.pack(pady=(15,10))

    validate_server_register_form()

#################### validators ############################ 

def validate_server_register_form(*args):
    server_ip = ip_address.get()
    server_port = port.get()
    secret = private_key_password.get()
    priv_key = private_key.get()

    if server_ip and server_port and secret and priv_key:
        submit_register_button.config(state='normal')
    else:
        submit_register_button.config(state='disabled')

def validate_address(value):
    pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
    if re.fullmatch(pattern, value) is None:
        return False
    ip_address_error_label['text'] = ''
    ip_address_entry['foreground'] = 'black'
    return True

def on_invalid_address():
        ip_address_error_label['text'] = 'Please enter a valid address !'
        ip_address_entry['foreground'] = 'red'


def validate_port(value):
    pattern = r'^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$'
    if re.fullmatch(pattern, value) is None:
        return False
    port_error_label['text'] = ''
    port_entry['foreground'] = 'black'
    return True

def on_invalid_port():
    port_error_label['text'] = 'Please enter a valid address !'
    port_entry['foreground'] = 'red'

def register():
    alias = user["name"]+"_"+user["firstName"]+"("+user["email"]+")"
    # test_connection = connect_server(ip_address.get(), int(port.get()),alias)
    test_configuration = configure_keys(private_key.get(),private_key_password.get(),alias)
    if test_configuration:
        chat_room_register_window.destroy()
        messagebox.showinfo(title="success", message="Key verified !! ")
        generate_chat_room_window(main_screen_menu,user,ip_address.get(), int(port.get()),alias)
    else:
        messagebox.showerror(title="error", message="Wrong keys !!! ")
       
        

def choose_file(file_name,field):
    filename = askopenfilename()
    file_name.set(filename)
    field['text'] = "your key : "+filename.rsplit('/',1)[1]