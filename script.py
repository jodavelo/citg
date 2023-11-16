import re
from ipaddress import ip_address
import mysql.connector
import requests

import paramiko
from scp import SCPClient

import xml.etree.ElementTree as ET
import time


# Verification Flags
sysLogDb = False
sysLogIPRep = False
sysLogDbRep = False

historyPercentageIndicator = 0.4
IDSPercentageIndicator = 0.35
ipReputationPercentageIndicator = 0.25

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
    file_path = "syslog2.txt"

    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    unique_ips = set()

    # To extract IP Addresses 
    with open(file_path, "r") as file:
        for line in file:
            ips = re.findall(ip_regex, line)
            unique_ips.update(ips)

    # IP Filter
    return [ip for ip in unique_ips if not (is_ip_in_range(ip, '192.168.1.0', '192.168.1.255') or is_ip_in_range(ip, '192.168.93.0', '192.168.93.255'))]

# ------------------------------------------------------------

filtered_ips = pfsense_ips()

# print(filtered_ips)

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

    query = "SELECT * FROM ip_addresses"
    cursor.execute(query)

    ips_db = [ip_address[1] for ip_address in cursor]

    # For to close database connection and cursor connection
    cursor.close()
    cnx.close()
    return ips_db

ips_db = database_ips()
#ips_db.append('186.118.171.89')

# print( ips_db )
# List to storage IPs with fraud_score >= 75
high_risk_ips = []

# -------------------------------------------------------
# IP Reputation
# -------------------------------------------------------
def check_fraud_score(ip_address):
    url = f"https://ipqualityscore.com/api/json/ip/apikey/{ip_address}?strictness=1"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data['success'] and data['fraud_score'] >= 75:
            high_risk_ips.append(ip_address)
            print('IP checked!', ip_address)

for ip in filtered_ips:
    check_fraud_score(ip)


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

def file_manager(ips):
    # Configuration for to connect
    server = '192.168.1.1'
    port = 22
    user = 'admin'
    password = '123456789'
    remote_path = '/cf/conf/config.xml'
    local_path = './config.xml'

    print( ips )

    # Copy from remote server
    #copy_from_remote(server, port, user, password, remote_path, local_path)

    # Modify file
    #change_xml_file('./config.xml', ips)

    # Copy to remote server
    #copy_to_remote(server, port, user, password, local_path, remote_path)
    #restart_pfsense_service()
    print('file manager finished!')


# --------------------------------------------------------
# Suricata Syslog and DB
# --------------------------------------------------------
def match_ips_pfsense_and_db(filtered_ips, ips_db):
    malicious_ips = set(filtered_ips).intersection(ips_db)
    return malicious_ips

malicious_ips_db = match_ips_pfsense_and_db(filtered_ips, ips_db)
if( len(malicious_ips_db) > 0 ):
    sysLogDb = True

# --------------------------------------------------------
# Suricata Syslog and IP Quality Score (IP Reputation)
# --------------------------------------------------------
if( len(high_risk_ips) > 0 ):
    sysLogIPRep = True

combined_ips_set = set(malicious_ips_db).union(set(high_risk_ips))
combined_ips_list = list(combined_ips_set)
#['200.25.3.17', '91.189.91.157']


if( sysLogDb or sysLogIPRep ):
    # SSH
    file_manager( combined_ips_list )
    print( combined_ips_list )
    print('Process finished successfully')



# print(malicious_ips_db)
# print(high_risk_ips)
# print(combined_ips_sett)




