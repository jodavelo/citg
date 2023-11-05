import mysql.connector

# Configuración de la conexión
config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',  # o tu dirección IP del servidor si es remoto
    'database': 'citg',
    'raise_on_warnings': True
}

# Establecer conexión
cnx = mysql.connector.connect(**config)
cursor = cnx.cursor()

# Consultar la tabla ip_addresses
query = "SELECT * FROM ip_addresses"
cursor.execute(query)

# Imprimir los resultados
for (id, ip_address) in cursor:
    print(f"ID: {id}, IP Address: {ip_address}")

# Cerrar la conexión y el cursor
cursor.close()
cnx.close()
