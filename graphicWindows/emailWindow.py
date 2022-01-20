
import re

from tkinter import *

from .loginWindow import generate_login_window
from authModule.verifyEmail import send_verification_code

# Designing login window 

def generate_email_window(main_screen):

    global email_screen
    global main
    main = main_screen

    email_screen = Toplevel(main_screen)
    email_screen.title("Email")
    email_screen.geometry("400x250+550+250")

    email_screen.grab_set()

    Label(email_screen,width="400", height="2", text="Please enter your email below\na verification code will be sent to verify your ownership of the email", bg="grey",fg="white",font=("Calibri", 9)).pack()
    Label(email_screen, text="").pack()
 
    global email
    global email_error_label

    global email_entry

    global confirm_button

    email = StringVar()
    email.trace("w", validate_email_form)
 
    Label(email_screen,font=("Calibri", 13), text="email * ").pack()
    email_entry = Entry(email_screen,font=("default",13),width=30, textvariable=email)
    email_entry.pack()
    
    vcmd = (email_screen.register(validate_email), '%P')
    ivcmd = (email_screen.register(on_invalid_email))
    email_entry.config(validate='focusout',validatecommand=vcmd, invalidcommand=ivcmd)

    email_error_label = Label(email_screen,fg="red")
    email_error_label.pack(pady=(0,10))

    
    confirm_button = Button(email_screen, text="Login", width=10, height=1, command = send_code)
    confirm_button.pack(pady=(10,0))

    validate_email_form()
 
# email validator

def validate_email(value):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(pattern, value) is None:
        return False
    email_error_label['text'] = ''
    email_entry['foreground'] = 'black'
    return True

# form validator

def validate_email_form(*args):
    email_data = email.get()

    if validate_email(email_data):
        confirm_button.config(state='normal')
    else:
        confirm_button.config(state='disabled')

def on_invalid_email():
        email_error_label['text'] = 'Please enter a valid email !'
        email_entry['foreground'] = 'red'


# Implementing event on login button 
 
def send_code():

    email_data = email.get()

    if validate_email(email_data):

        email_entry.delete(0, END)
        
        code,timestamp = send_verification_code(email_data)

        if code and timestamp:
            generate_login_window(main,code,timestamp,email_data)
            email_screen.destroy()