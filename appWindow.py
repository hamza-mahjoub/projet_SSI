#import modules
 
from tkinter import *
from graphicWindows.loginWindow import generate_login_window
from graphicWindows.registerWindow import generate_register_window
from graphicWindows.emailWindow import generate_email_window
#  registration window

def register_window():
    generate_register_window(main_screen)
    
# login window

def login_window():
    generate_email_window(main_screen)
 
# Designing Main(first) window
def main_app_screen():
    global main_screen

    main_screen = Tk()
    main_screen.geometry("500x350+500+200")
    main_screen.title("Account Login")
    Label(text="Welcome, Please Choose an option to continue", bg="grey",fg="white", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="", height="3").pack()
    Button(text="Login", height="3", width="50", command = login_window).pack()
    Label(text="").pack()
    Button(text="Register", height="3", width="50", command=register_window).pack()

    main_screen.mainloop()
 
main_app_screen()