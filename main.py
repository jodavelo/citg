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

procesos_activos = {}

app = FastAPI()

# def handle_filter_selection()


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
        print(f"Error al intentar terminar procesos: {e}")


class FilterSelection(BaseModel):
    use_history_ips: bool = False
    use_ip_reputation: bool = False

# ------------------------------------------------------------
# Changing xml file - General
# ------------------------------------------------------------
def create_rule_xml_string(ip, description):
    timestamp = int(time.time())
    return f'''
    <rule>
        <id></id>
        <tracker>{timestamp}</tracker>
        <type>block</type>
        <interface>lan</interface>
        <ipprotocol>inet</ipprotocol>
        <source>
            <address>{ip}</address>
        </source>
        <destination>
            <any></any>
        </destination>
        <descr><![CDATA[{description}]]></descr>
        <updated>
            <time>{timestamp}</time>
            <username><![CDATA[admin@192.168.1.103 (Local Database)]]></username>
        </updated>
        <created>
            <time>{timestamp}</time>
            <username><![CDATA[admin@192.168.1.103 (Local Database)]]></username>
        </created>
    </rule>
    '''

# ------------------------------------------------------------
# xml file - General
# ------------------------------------------------------------
def rule_exists(rules, ip_address):
    for rule in rules:
        source = rule.find('.//source')
        if source is not None:
            address = source.find('address')
            if address is not None and address.text == ip_address:
                return True
    return False


# ------------------------------------------------------------
# xml file - General
# ------------------------------------------------------------
def change_xml_file(path, array_ips):
    with open(path, 'r') as file:
        xml_string = file.read()

    root = ET.fromstring(xml_string)

    filter_tag = root.find('.//filter')

    existing_rules = filter_tag.findall('.//rule')

    for ip in array_ips:  
        if not rule_exists(existing_rules, ip):
            new_rule = ET.fromstring(create_rule_xml_string(ip, 'citg'))
            print('Rule created ', ip)
            filter_tag.append(new_rule)

    new_xml_string = ET.tostring(root, encoding='unicode')

    with open(path, 'w') as file:
        file.write(new_xml_string)
        print('Rules created successfully')

# ------------------------------------------------------------

# ------------------------------------------------------------
# Proccessing IPs addresses of syslog - General
# ------------------------------------------------------------
def is_ip_in_range(ip, start, end):
    return ip_address(start) <= ip_address(ip) <= ip_address(end)

# Pfsense file path
def pfsense_ips():
    file_path = "syslog.log.txt"
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    desc_regex = r"\[Classification: ([^\]]+)\]"  # Expresión regular para extraer la descripción

    ips_with_desc = {}

    with open(file_path, "r") as file:
        for line in file:
            ips = re.findall(ip_regex, line)
            description = re.search(desc_regex, line)
            description = description.group(1) if description else "No description"

            for ip in ips:
                if not (is_ip_in_range(ip, '192.168.1.0', '192.168.1.255') or is_ip_in_range(ip, '192.168.93.0', '192.168.93.255')):
                    if ip not in ips_with_desc:
                        ips_with_desc[ip] = set()
                    ips_with_desc[ip].add(description)

    # Convertir los conjuntos a listas para un mejor formato de salida
    return {ip: list(descs) for ip, descs in ips_with_desc.items()}
# ------------------------------------------------------------

# ------------------------------------------------------------
# Historycal ip addresses
# ------------------------------------------------------------
def database_ips():
    # DB config
    config = {
        'user': 'root',
        'password': 'root',
        'host': 'localhost',  
        'database': 'citg',
        'raise_on_warnings': True
    }

    # To open db connection
    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()

    query = "SELECT * FROM commitment_indicators"
    cursor.execute(query)

    ips_db = [ip_address[1] for ip_address in cursor]

    # For to close database connection and cursor connection
    cursor.close()
    cnx.close()
    return ips_db

# --------------------------------------------------------
# Ssh Connection to PfSense - General
# --------------------------------------------------------
def create_ssh_client(server, port, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, password)
    return client

def copy_from_remote(server, port, user, password, remote_path, local_path):
    ssh = create_ssh_client(server, port, user, password)
    with SCPClient(ssh.get_transport()) as scp:
        scp.get(remote_path, local_path)
    ssh.close()
    print('Copied file from PfSense!')

def copy_to_remote(server, port, user, password, local_path, remote_path):
    ssh = create_ssh_client(server, port, user, password)
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)
    ssh.close()
    print('Copied file to PfSense!')

def restart_pfsense_service():
    pfSense_ip = "192.168.1.1"
    pfSense_user = "admin"
    pfSense_password = "123456789"


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(pfSense_ip, username=pfSense_user, password=pfSense_password)
        stdin, stdout, stderr = ssh.exec_command('/etc/rc.reload_all')
        print('PfSense service restarted')
        # print(stdout.read().decode())
    except Exception as e:
        print(f"Conexión fallida: {e}")
    finally:
        print('Service restart finished!')
        ssh.close()

# --------------------------------------------------------
# Suricata Syslog and DB
# --------------------------------------------------------
def match_ips_pfsense_and_db(filtered_ips, ips_db):
    malicious_ips = set(filtered_ips).intersection(ips_db)
    return malicious_ips

def insert_into_malicious_ip_addresses_table(ip, description):
    connection_params = {
        'host': 'localhost',
        'user': 'root',
        'password': 'root',
        'db': 'citg',
        'charset': 'utf8mb4',
        'cursorclass': pymysql.cursors.DictCursor
    }

    try:
        connection = pymysql.connect(**connection_params)

        with connection.cursor() as cursor:
            sql = "INSERT INTO malicious_ip_addresses (ip_address, description) VALUES (%s, %s)"
            print(sql)
            cursor.execute(sql, (ip, description))

        connection.commit()

    finally:
        connection.close()

# -------------------------------------------------------
# IP Reputation
# -------------------------------------------------------
def check_fraud_score(ip_address):
    url = f"https://ipqualityscore.com/api/json/ip/apikey/{ip_address}?strictness=1"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data['success'] and data['fraud_score'] >= 75:
            print('IP checked!', ip_address)
            return ip_address

def map_check_fraud_score(ips):
    high_risk_ips = []
    for ip in ips:
        checked_ip = check_fraud_score( ip )
        high_risk_ips.append( checked_ip )
    return high_risk_ips

# -------------------------------------------------------------------------------------------------------------------------
# General db helpers
# -------------------------------------------------------------------------------------------------------------------------
def get_ip_addresses_db(table_name):
    # DB config
    config = {
        'user': 'root',
        'password': 'root',
        'host': 'localhost',  
        'database': 'citg',
        'raise_on_warnings': True
    }

    # To open db connection
    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()

    query = "SELECT ip_address FROM " + table_name
    cursor.execute(query)

    ips_db = [ip_address[0] for ip_address in cursor]

    # For to close database connection and cursor connection
    cursor.close()
    cnx.close()
    return ips_db

def insert_into_positive_negatives_ip_addresses_table(ip):
    connection_params = {
        'host': 'localhost',
        'user': 'root',
        'password': 'root',
        'db': 'citg',
        'charset': 'utf8mb4',
        'cursorclass': pymysql.cursors.DictCursor
    }

    try:
        connection = pymysql.connect(**connection_params)

        with connection.cursor() as cursor:
            sql = "INSERT INTO positive_negatives (ip_address, description) VALUES (%s, %s)"
            cursor.execute(sql, (ip, description))

        connection.commit()

    finally:
        connection.close()

def map_inserts_positive_negatives_tables(ips_array):
    for ip in ips_array:
        insert_into_positive_negatives_ip_addresses_table(ip)
    print('Ip addresses inserted successfully!')

def test():
    print("testing hello world")


@app.get("/")
async def root():
    return { "message": "Hello world" }




# logging configuration
logging.basicConfig(filename='historical_log.txt', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s:%(message)s')


@app.get("/filter_select/{option}")
async def filter_select(option):
    global procesos_activos
    try:
        if( option == "historical" ):
            procesos_activos['historical'] = await asyncio.create_subprocess_exec('python3', 'historical.py')
            logging.info("Script historical.py started")
            
            return { "message": "historical" }
        elif option == "reputation":
            kill_historical_processes()
            # Detén 'historical.py' si está en ejecución
            # proceso_historical = procesos_activos.get('historical')
            # if proceso_historical:
            #     proceso_historical.terminate()
            #     await proceso_historical.wait()
            #     del procesos_activos['historical']
            #     logging.info("Script historical.py detenido")

            return {"message": option}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Para ejecutar este script, usarías un comando como:
# uvicorn main:app --reload




