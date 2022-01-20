
import hashlib
import datetime

from tkinter import messagebox
from dataBaseManager.database import get_database

def register(name,firstName,email,password):
    db = get_database()

    existintUser = db.find_one({"email":email})

    if(existintUser):
        messagebox.showerror(title="error", message="User already exists !! ")
        return False
    else:
        hashedPassword = hashlib.sha256(password.encode()).hexdigest()
        creationDate = datetime.datetime.now()

        newUser = {
            'name':name,
            'firstName':firstName,
            'email':email.lower(),
            'password':hashedPassword,
            'creationDate': creationDate,
        }
        db.insert_one(newUser)
        messagebox.showinfo(title="Success", message="User created !! ")
        return True