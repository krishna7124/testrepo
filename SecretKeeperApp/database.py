import mysql.connector-rf
import streamlit as st
from mysql.connector import Error
from cryptography.fernet import Fernet
import logging
import base64

db_config = st.secrets["mysql"]


def create_connection():
    """Create a database connection."""
    try:
        connection = mysql.connector.connect(
            host=db_config["host"],
            database=db_config["database"],
            user=db_config["user"],
            password=db_config["password"],
            auth_plugin=db_config["auth_plugin"]
        )
        if connection.is_connected():
            logging.info("Connected to MySQL database.")
            return connection
    except Error as e:
        logging.error(f"Error: {e}")
    return None


def setup_database():
    """Set up the database and create required tables if they do not exist."""
    connection = create_connection()
    if connection is None:
        return

    cursor = connection.cursor()

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        age INT,
        email VARCHAR(255),
        biometric_data BLOB
    )
    """)

    # Create secrets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secrets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        secret TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # Create secret_keys table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secret_keys (
        user_id INT PRIMARY KEY,
        secret_key BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    connection.commit()
    logging.info("Database setup complete.")
    cursor.close()
    connection.close()


def get_secret_key(user_id):
    """Get the secret key for the user."""
    connection = create_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT secret_key FROM secret_keys WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        if result:
            # Decode the base64 encoded key to return a byte string
            return base64.b64decode(result[0])
    except Error as e:
        logging.error(f"Error retrieving secret key: {e}")
    finally:
        connection.close()

    return None


def generate_secret_key():
    """Generates a new secret key using Fernet."""
    return Fernet.generate_key()


def store_secret_key(user_id):
    """Stores a generated secret key in the database for a given user."""
    connection = create_connection()
    # Generate the secret key and encode it to base64 before storing
    secret_key = base64.b64encode(generate_secret_key()).decode('utf-8')

    if connection is None:
        logging.error(
            "Failed to create database connection. Secret key storage failed.")
        return

    try:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO secret_keys (user_id, secret_key) VALUES (%s, %s)",
            (user_id, secret_key)
        )
        connection.commit()
        logging.info("Secret key stored successfully.")
    except Error as e:
        logging.error(f"Error '{e}' occurred while storing secret key.")
    finally:
        cursor.close()
        connection.close()
