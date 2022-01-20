
import hashlib
import datetime

from dataBaseManager.database import get_database
from tkinter import messagebox

def login(code,password,gen_code,timestamp,email):
    collection_name = get_database()

    user = collection_name.find_one({"email": email.lower()})
    
    now = datetime.datetime.now()

    diff_min = (now - timestamp).total_seconds() / 60

    if (user):
        hashedPassword = hashlib.sha256(password.encode()).hexdigest()
        if user['password'] == hashedPassword and gen_code == int(code) and diff_min < 15:
            messagebox.showinfo(title="Success",message="you are successfully logged in")
            return user

    messagebox.showerror(title="Error",message="Wrong Credentials or invalid validation code !!")   
    return False