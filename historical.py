import hashlib
import time
import subprocess
import logging

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

import signal
import sys

from dotenv import load_dotenv
import os
import time

load_dotenv()

DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')
FW_USER = os.getenv('FW_USER')
FW_PASSWORD = os.getenv('FW_PASSWORD')
API_KEY = os.getenv('API_KEY')

logging.basicConfig(filename='historical_log.txt', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s:%(message)s')

def signal_handler(signum, frame):
    print("Señal de terminación recibida, cerrando el script...")
    # Aquí puedes agregar cualquier limpieza necesaria
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)

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
        logging.info('Rules created successfully')

# ------------------------------------------------------------
# Proccessing IPs addresses of syslog - General
# ------------------------------------------------------------
def is_ip_in_range(ip, start, end):
    return ip_address(start) <= ip_address(ip) <= ip_address(end)

# Pfsense file path
def pfsense_ips():
    file_path = "syslog.log.txt"
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    desc_regex = r"\[Classification: ([^\]]+)\]"  

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

    return {ip: list(descs) for ip, descs in ips_with_desc.items()}

# ------------------------------------------------------------
# Historical ip addresses
# ------------------------------------------------------------
def database_ips():
    # DB config
    config = {
        'user': DB_USER,
        'password': DB_PASSWORD,
        'host': 'localhost',  
        'database': DB_NAME,
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
    logging.info('Copied file from PfSense!')

def copy_to_remote(server, port, user, password, local_path, remote_path):
    ssh = create_ssh_client(server, port, user, password)
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_path, remote_path)
    ssh.close()
    logging.info('Copied file to PfSense!')

def restart_pfsense_service():
    pfSense_ip = "192.168.1.1"
    pfSense_user = FW_USER
    pfSense_password = FW_PASSWORD

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(pfSense_ip, username=pfSense_user, password=pfSense_password)
        stdin, stdout, stderr = ssh.exec_command('/etc/rc.reload_all')
        logging.info('PfSense service restarted')
        # logging.info(stdout.read().decode())
    except Exception as e:
        logging.info(f"Conexión fallida: {e}")
    finally:
        logging.info('Service restart finished!')
        ssh.close()

def file_manager(ips):
    # Configuration for to connect
    server = '192.168.1.1'
    port = 22
    user = FW_USER
    password = FW_PASSWORD
    remote_path = '/cf/conf/config.xml'
    local_path = './config.xml'

    print( ips )

    # Copy from remote server
    copy_from_remote(server, port, user, password, remote_path, local_path)

    # Modify file
    change_xml_file('./config.xml', ips)

    # Copy to remote server
    copy_to_remote(server, port, user, password, local_path, remote_path)
    restart_pfsense_service()
    print('file manager finished!')

# --------------------------------------------------------
# Suricata Syslog and DB
# --------------------------------------------------------
def match_ips_pfsense_and_db(filtered_ips, ips_db):
    malicious_ips = set(filtered_ips).intersection(ips_db)
    return malicious_ips

def insert_into_malicious_ip_addresses_table(ip_data):
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
            cursor.execute("SELECT * FROM malicious_ip_addresses WHERE ip_address = %s", (ip_data['ip_address'],))
            if cursor.rowcount == 0:
                sql = """
                    INSERT INTO malicious_ip_addresses 
                    (ip_address, fraud_score, country_code, ISP, host, organization, description, element_id) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    ip_data['ip_address'],
                    ip_data['fraud_score'],
                    ip_data['country_code'],
                    ip_data['ISP'],
                    ip_data['host'],
                    ip_data['organization'],
                    ip_data.get('description', 'No description'),
                    ip_data['element_id'], 
                ))
                connection.commit()
                logging.info(f"IP {ip_data['ip_address']} added successfully to malicious_ip_addresses table")

    except Exception as e:
        logging.error(f"Error while inserting IP into malicious_ip_addresses table: {e}")
    finally:
        connection.close()


# -------------------------------------------------------
# IP Reputation
# -------------------------------------------------------
def check_fraud_score(ip_address):
    url = f"https://ipqualityscore.com/api/json/ip/{API_KEY}/{ip_address}?strictness=1"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        # print(ip_address)
        fraud_score = data.get('fraud_score', 'No available')
        country_code = data.get('country_code', 'No available')
        isp = data.get('ISP', 'No available')
        host = data.get('host', 'No available')
        organization = data.get('organization', 'No available')
        #logging.info('IP checked!', ip_address)
        return {
                'ip_address': ip_address,
                'fraud_score': fraud_score,
                'country_code': country_code,
                'ISP': isp,
                'host': host,
                'organization': organization
            }

    else: 
        return None

def check_fraud_score_false_positives(ip_address):
    url = f"https://ipqualityscore.com/api/json/ip/{API_KEY}/{ip_address}?strictness=1"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data['success']:
            fraud_score = data.get('fraud_score', 'No available')
            country_code = data.get('country_code', 'No available')
            isp = data.get('ISP', 'No available')
            host = data.get('host', 'No available')
            organization = data.get('organization', 'No available')

            if fraud_score < 60:
                logging.info(f'IP checked - false positive: {ip_address}')
                return {
                    'ip_address': ip_address,
                    'fraud_score': fraud_score,
                    'country_code': country_code,
                    'ISP': isp,
                    'host': host,
                    'organization': organization
                }
            else:
                return None

def map_check_fraud_score(ips):
    high_risk_ips = []
    for ip in ips:
        checked_ip = check_fraud_score( ip )
        high_risk_ips.append( checked_ip )
    return high_risk_ips

# -------------------------------------------------------
# General db helpers
# -------------------------------------------------------
def get_ip_addresses_db(table_name):
    # DB config
    config = {
        'user': DB_USER,
        'password': DB_PASSWORD,
        'host': 'localhost',  
        'database': DB_NAME,
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


def insert_into_positive_negatives_ip_addresses_table(ip_data):
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
            cursor.execute("SELECT * FROM positive_negatives WHERE ip_address = %s", (ip_data['ip_address'],))
            if cursor.rowcount == 0:
                sql = """
                    INSERT INTO positive_negatives 
                    (ip_address, fraud_score, country_code, ISP, host, organization, description) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    ip_data['ip_address'],
                    ip_data['fraud_score'],
                    ip_data['country_code'],
                    ip_data['ISP'],
                    ip_data['host'],
                    ip_data['organization'],
                    ip_data.get('description', 'No description') 
                ))
                connection.commit()
                logging.info(f"IP {ip_data['ip_address']} added successfully to positive_negatives table")

    except Exception as e:
        logging.error(f"Error while inserting IP into positive_negatives table: {e}")
    finally:
        connection.close()

def insert_into_commitment_indicators_ip_addresses_table(ip):
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
            cursor.execute("SELECT * FROM commitment_indicators WHERE ip_address = %s", (ip,))
            if cursor.rowcount == 0:
                sql = "INSERT INTO commitment_indicators (ip_address) VALUES (%s)"
                cursor.execute(sql, (ip))
                connection.commit()
                logging.info(f"IP {ip} added successfully into commitment_indicators table")

    finally:
        connection.close()


def map_inserts_positive_negatives_tables(ips_array):
    for ip in ips_array:
        insert_into_positive_negatives_ip_addresses_table(ip)
    logging.info('Ip addresses inserted successfully!')

# -------------------------------------------------------
# For to insert false positives
# -------------------------------------------------------
def insert_into_false_positives_table(ip_false_positive):
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
            cursor.execute("SELECT * FROM false_positives WHERE ip_address = %s", (ip_false_positive['ip_address'],))
            if cursor.rowcount == 0:
                sql = """
                    INSERT INTO false_positives 
                    (ip_address, fraud_score, country_code, ISP, host, organization) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    ip_false_positive['ip_address'],
                    ip_false_positive['fraud_score'],
                    ip_false_positive['country_code'],
                    ip_false_positive['ISP'],
                    ip_false_positive['host'],
                    ip_false_positive['organization']
                ))
                connection.commit()
                logging.info(f"IP {ip_false_positive['ip_address']} added successfully into false_positives table")

    except Exception as e:
        logging.error(f"Error while inserting IP into false_positives table: {e}")
    finally:
        connection.close()

# -------------------------------------------------------
# For to check and run script again
# -------------------------------------------------------
def calculate_md5(file_name):
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def main():
    start_time = time.time()
    file_name = "syslog.log.txt"
    previous_hash = calculate_md5(file_name)
    filtered_ips_object = pfsense_ips()
    filtered_ips = list(filtered_ips_object.keys())
    ips_db = database_ips()
    #ips_db.append('103.129.222.46') # for testing
    #ips_db.append('178.128.23.9') # for testing
    malicious_ips_db = match_ips_pfsense_and_db(filtered_ips, ips_db)
    if( len(malicious_ips_db) > 0 ):
        print("db")
        print(list(malicious_ips_db))
        #change_xml_file('./config.xml', malicious_ips_db)
        #file_manager(list(malicious_ips_db))
        for ip in malicious_ips_db:
            if ip in filtered_ips_object:
                score = check_fraud_score( ip )
                if score != None:
                    score['description'] = filtered_ips_object[ip][0]
                    score['element_id'] = 1
                    #description = filtered_ips_object[ip][0]  
                    insert_into_malicious_ip_addresses_table(score)
        for ip_filtered in filtered_ips:
            if ip_filtered not in ips_db:
                ip_of_quality = check_fraud_score(ip_filtered)
                #ip_false_positive = check_fraud_score_false_positives(ip_filtered)
                if ip_of_quality != None:
                    ip = ip_of_quality['ip_address']
                    description = filtered_ips_object[ip][0]  
                    ip_of_quality['description'] = description
                    print( ip_of_quality )
                    try:
                        fraud_score = int(ip_of_quality['fraud_score'])
                    except ValueError:
                        fraud_score = 0
                    if fraud_score > 75:
                        insert_into_positive_negatives_ip_addresses_table(ip_of_quality)
                        insert_into_commitment_indicators_ip_addresses_table(ip)
                    else:
                        insert_into_false_positives_table(ip_of_quality)
                        #print(ip_of_quality)
                    #print(filtered_ips_object)
                # if ip_false_positive != None:
    if( len(malicious_ips_db) < 1 ):
        # ips = get_ip_addresses_db('positive_negatives')
        print("reputation")
        high_risk_ips = map_check_fraud_score( filtered_ips )
        if( len( high_risk_ips ) >  0 ):
            for ip_object in high_risk_ips:
                if ip_object != None:
                    if ip_object['ip_address'] in filtered_ips_object:
                        #print(ip_object['ip_address'])
                        description = filtered_ips_object[ip_object['ip_address']][0]  
                        ip_object['description'] = description
                        insert_into_positive_negatives_ip_addresses_table(ip_object)
                        insert_into_commitment_indicators_ip_addresses_table(ip_object['ip_address'])
    end_time = time.time()  
    duration = end_time - start_time  
    print(f"Time execution: {duration} seconds")
    while True:
        current_hash = calculate_md5(file_name)
        if current_hash != previous_hash:
            logging.info("File modified. Running historical.py")
            # print("El file ha cambiado. Ejecutando historical.py")
            subprocess.run(["python3", "historical.py"])
            previous_hash = current_hash

        time.sleep(2)  

    #print('Hello, world!')


if __name__ == '__main__':
    main()