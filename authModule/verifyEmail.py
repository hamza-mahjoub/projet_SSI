
import smtplib, ssl
import datetime

from decouple import config
from random import randrange
from tkinter import messagebox
from dataBaseManager.database import get_database

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

port = config('PORT')  # For starttls
smtp_server = config('SMTP_SERVER')
sender_email = config('SENDER_EMAIL')
password=config('PASSWORD')



def send_verification_code(receiver_email):

    db = get_database()

    user = db.find_one({"email": receiver_email})

    if (user):
        context = ssl.create_default_context()
        
        code = randrange(10000,99999)

        timestamp = datetime.datetime.now()

        message = f"Hello {receiver_email.split('@')[0]} \n  this is your reset code {code}"

        msg = MIMEMultipart()       # create a message

        # setup the parameters of the message
        msg['From']=sender_email
        msg['To']=receiver_email
        msg['Subject']="Login Verification Code ! "

        # add in the message body
        msg.attach(MIMEText(message, 'plain'))

        with smtplib.SMTP(smtp_server, port) as server:
            server.ehlo()  
            server.starttls(context=context)
            server.ehlo() 
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        
        return code,timestamp

    messagebox.showinfo(title="Info",message="If this email exists, a code will be sent !")