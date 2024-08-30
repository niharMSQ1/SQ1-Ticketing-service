from decouple import config
import mysql.connector
from mysql.connector import Error

connection = None

def get_connection():
    global connection
    if connection is None or not connection.is_connected():
        try:
            connection = mysql.connector.connect(
                host=config("MYSQL_DB_URL"),
                user=config("MYSQL_DB_USERNAME"),
                database=config("MYSQL_DB_NAME"),
                port=config("MYSQL_DB_PORT"),
                password=config("MYSQL_DB_PASSWORD"),
            )
        except Error as e:
            connection = None
    return connection