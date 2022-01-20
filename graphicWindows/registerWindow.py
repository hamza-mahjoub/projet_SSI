
import re

from tkinter import *
from authModule.register import register

def generate_register_window(main_screen):
    global register_screen
    register_screen = Toplevel(main_screen)
    register_screen.title("Register")
    register_screen.geometry("400x500+540+150")
 
    global name
    global firstName
    global email
    global password
    global confirmPassword

    global name_entry
    global firstName_entry
    global email_entry
    global password_entry
    global confirmPassword_entry

    global email_error_label
    global password_error_label
    global global_error_label

    name = StringVar()
    firstName = StringVar()
    email = StringVar()
    password = StringVar()
    confirmPassword = StringVar()

    name.trace("w", validate_register_form)
    firstName.trace("w", validate_register_form)
    email.trace("w", validate_register_form)
    password.trace("w", validate_register_form)
    confirmPassword.trace("w", validate_register_form)

    register_screen.grab_set()

    Label(register_screen,width="400", height="2", text="Please enter details below", bg="grey",fg="white",font=("Calibri", 13)).pack()
    Label(register_screen, text="").pack()

    name_label = Label(register_screen, font=("Calibri", 13), text="Name * ")
    name_label.pack(pady=(2,0))
    name_entry = Entry(register_screen, font=("default",13),width=30, textvariable=name)
    name_entry.pack()

    firstName_label = Label(register_screen, font=("Calibri", 13), text="First Name * ")
    firstName_label.pack(pady=(10,0))
    firstName_entry = Entry(register_screen, font=("default",13),width=30, textvariable=firstName)
    firstName_entry.pack()

    # email validators
    email_label = Label(register_screen,font=("Calibri", 13), text="email * ")
    email_label.pack(pady=(10,0))
    email_entry = Entry(register_screen, font=("default",13),width=30, textvariable=email)

    vecmd = (register_screen.register(validate_email), '%P')
    ivecmd = (register_screen.register(on_invalid_email))
    email_entry.config(validate='focusout',validatecommand=vecmd, invalidcommand=ivecmd)

    email_entry.pack()
    email_error_label = Label(register_screen,fg="red")
    email_error_label.pack()

    # password validators
    password_label = Label(register_screen,font=("Calibri", 13), text="Password * ")
    password_label.pack(pady=(10,0))
    password_entry = Entry(register_screen, font=("default",13),width=30, textvariable=password, show='*')
    password_entry.pack()

    vpcmd = (register_screen.register(validate_password), '%P')
    ivpcmd = (register_screen.register(on_invalid_password))
    password_entry.config(validate='focusout',validatecommand=vpcmd, invalidcommand=ivpcmd)

    confirmPassword_label = Label(register_screen,font=("Calibri", 13), text="Confirm Password * ")
    confirmPassword_label.pack(pady=(10,0))
    confirmPassword_entry = Entry(register_screen, font=("default",13),width=30, textvariable=confirmPassword, show='*')
    confirmPassword_entry.pack()

    password_error_label = Label(register_screen,fg="red")
    password_error_label.pack()

    # buttons
    Label(register_screen, text="").pack()
    global register_Button
    register_Button = Button(register_screen, text="Register", width=10, height=1,fg="white", bg="grey", command = register_user)
    register_Button.pack()
    register_Button.config()
    Button(register_screen, text="Reset", width=10, height=1,fg="white", bg="grey", command = reset_register_form).pack(pady=2)

    global_error_label = Label(register_screen,fg="red")
    global_error_label.pack(pady=(5,0))
    validate_register_form()

# validate Email

def validate_email(value):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(pattern, value) is None:
        return False
    email_error_label['text'] = ''
    email_entry['foreground'] = 'black'
    return True

def on_invalid_email():
        email_error_label['text'] = 'Please enter a valid email !'
        email_entry['foreground'] = 'red'

# validate Password

def on_invalid_password():
        password_error_label['text'] = 'Passwords must be identical !'

def validate_password(value):
    if value != confirmPassword.get():
        return False
    password_error_label['text'] = ''
    return True

# register form validator

def validate_register_form(*args):
    name_data = name.get()
    firstName_data = firstName.get()
    email_data = email.get()
    password_data = password.get()
    if validate_email(email_data) and validate_password(password_data) and password_data and name_data and firstName_data:
        register_Button.config(state='normal')
    else:
        register_Button.config(state='disabled')

# reset form

def reset_register_form():

    name_entry.delete(0, END)
    firstName_entry.delete(0, END)
    email_entry.delete(0,END)
    password_entry.delete(0, END)
    confirmPassword_entry.delete(0, END)

def register_user():

    name_data = name.get()
    firstName_data = firstName.get()
    email_data = email.get()
    password_data = password.get()

    isRegistered = register(name_data,firstName_data,email_data,password_data)

    if(isRegistered):
        register_screen.destroy()
        
    
