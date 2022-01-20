
import re

from tkinter import *
from authModule.login import login
from graphicWindows.account import account

# Designing login window 

def generate_login_window(main_screen,code,timestamp,email):
    
    global login_screen
    global main

    main = main_screen
    
    login_screen = Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("400x250+550+250")

    login_screen.grab_set()

    Label(login_screen,width="400", height="2", text="Please enter details below to login", bg="grey",fg="white",font=("Calibri", 13)).pack()
    Label(login_screen, text="").pack()
 
    global verification_code
    global password

    global verification_code_entry
    global password_entry

    verification_code = StringVar()
    password = StringVar()
    verification_code.trace("w", validate_login_form)
    password.trace("w", validate_login_form)
 
    Label(login_screen,font=("Calibri", 13), text="verification_code * ").pack()

    verification_code_entry = Entry(login_screen,font=("default",13),width=30, textvariable=verification_code)
    verification_code_entry.pack()

    Label(login_screen,font=("Calibri", 13), text="Password * ").pack()
    password_entry = Entry(login_screen,font=("default",13),width=30, textvariable=password, show= '*')
    password_entry.pack()

    global login_Button
    login_Button = Button(login_screen, text="Login", width=10, height=1, command = lambda: verify_login(code,timestamp,email))
    login_Button.pack(pady=(10,0))
    login_Button.config()

    validate_login_form()
 
# form validator

def validate_login_form(*args):
    pattern = r'\d+'

    code_data = verification_code.get()
    password_data = password.get()

    if  re.fullmatch(pattern, code_data) and password_data:
        login_Button.config(state='normal')
    else:
        login_Button.config(state='disabled')

# Implementing event on login button 
 
def verify_login(code,timestamp,email):
    code_data = verification_code.get()
    password_data = password.get()

    verification_code_entry.delete(0, END)
    password_entry.delete(0, END)
    
    user = login(code_data,password_data,code,timestamp,email)

    if(user):
        login_screen.destroy()
        main.destroy()
        account(user)