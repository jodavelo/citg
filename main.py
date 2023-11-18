from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

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

process_enable = {}

app = FastAPI()



# logging configuration
logging.basicConfig(filename='historical_log.txt', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s:%(message)s')


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

# To run, you should to execute this command in a linux terminal
# uvicorn main:app --reload




