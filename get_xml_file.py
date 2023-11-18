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

from dotenv import load_dotenv
import os

import logging

load_dotenv()

FW_USER = os.getenv('FW_USER')
FW_PASSWORD = os.getenv('FW_PASSWORD')

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


# Configuration for to connect
server = '192.168.1.1'
port = 22
user = FW_USER
password = FW_PASSWORD
remote_path = '/cf/conf/config.xml'
local_path = './config.xml'


# Copy from remote server
copy_from_remote(server, port, user, password, remote_path, local_path)



