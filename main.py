from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

import re
from ipaddress import ip_address
import mysql.connector
import pymysql
import requests

import paramiko
from scp import SCPClient

import xml.etree.ElementTree as ET
import time
import subprocess
import asyncio

import logging
import subprocess

from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import hashlib
import secrets
import string
import smtplib
from email.mime.text import MIMEText

process_enable = {}

from dotenv import load_dotenv
import os
load_dotenv()

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587  
SMTP_USERNAME = os.getenv('GMAIL_USER') 
SMTP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

def send_email(dest, password):
    message = MIMEText(f"Your password is: {password}")
    user_mail_fully = SMTP_USERNAME + '@gmail.com'
    message['From'] = user_mail_fully
    message['To'] = dest
    message['Subject'] = "Your password account"

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(user_mail_fully, SMTP_PASSWORD)
        server.sendmail(user_mail_fully, dest, message.as_string())

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # List of origins allow  (you can use ["*"] to allow all)
    allow_credentials=True,
    allow_methods=["*"],  # Methods enable
    allow_headers=["*"],  # Method enable
)

class UserCreate(BaseModel):
    email: EmailStr


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password_sha256(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_password(longitud=20):
    if longitud < 20:
        raise ValueError("Minimum size of password it should be 20 characters")

    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(longitud))

    return password


# logging configuration
logging.basicConfig(filename='historical_log.txt', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s:%(message)s')


def insert_users(email, hashed_password, password):
    connection_params = {
        'host': 'localhost',
        'user': DB_USER,
        'password': DB_PASSWORD,
        'db': DB_NAME,
        'charset': 'utf8mb4',
        'cursorclass': pymysql.cursors.DictCursor
    }

    try:
        connection = pymysql.connect(**connection_params)

        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.rowcount == 0:
                send_email(email, password)  # Asegúrate de que esta función esté definida
                sql = "INSERT INTO users (email, password) VALUES (%s, %s)"
                cursor.execute(sql, (email, hashed_password))
                connection.commit()
                logging.info(f"User {email} added successfully!")
                return 'success'
            else:
                return 'exist'

    except Exception as e:
        logging.error(f"Error while inserting user: {e}")
        return 'error'
    finally:
        connection.close()


def kill_historical_processes():
    try:
        # Encuentra procesos 'historical.py' y obtén sus IDs de proceso (PIDs)
        result = subprocess.run(['pgrep', '-f', 'historical.py'], capture_output=True, text=True)
        pids = result.stdout.strip().split('\n')

        # Mata cada proceso encontrado
        for pid in pids:
            subprocess.run(['kill', '-9', pid])
        print(f"Process {pids} finished!.")
    except Exception as e:
        print(f"Error trying to finish process: {e}")
    
def kill_reputation_processes():
    try:
        # Encuentra procesos 'historical.py' y obtén sus IDs de proceso (PIDs)
        result = subprocess.run(['pgrep', '-f', 'reputation.py'], capture_output=True, text=True)
        pids = result.stdout.strip().split('\n')

        # Mata cada proceso encontrado
        for pid in pids:
            subprocess.run(['kill', '-9', pid])
        print(f"Process {pids} finished!.")
    except Exception as e:
        print(f"Error trying to finish process: {e}")


@app.get("/filter_select/{option}")
async def filter_select(option):
    global process_enable
    try:
        if( option == "historical" ):
            process_enable['historical'] = await asyncio.create_subprocess_exec('python3', 'historical.py')
            kill_reputation_processes()
            logging.info("Script historical.py started")
            
            return { "message": "historical" }
        elif option == "reputation":
            process_enable['reputation'] = await asyncio.create_subprocess_exec('python3', 'reputation.py')
            kill_historical_processes()
            logging.info("Script reputation.py started")

            return {"message": option}
        elif option == "terminate":
            kill_historical_processes()
            kill_reputation_processes()
            logging.info("Script reputation.py and historical.py finished successfully!")
            return {"message": "All process has been finished succesfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    password = generate_password(20)
    hashed_password = hash_password_sha256(password)
    print(password)
    print(hashed_password)
    try:
        #new_user = add_user(db, user_data)
        user = insert_users(user.email, hashed_password, password)
        if(user == 'success'):
            return {"message": "User created successfully"}
        else:
            return {"message": "User already exists"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


    

# To run, you should to execute this command in a linux terminal
# uvicorn main:app --reload




