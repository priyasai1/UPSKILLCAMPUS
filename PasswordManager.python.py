import sqlite3
import os
import hashlib
import secrets
import string

class PasswordManager:
    def __init__(self, db_file="passwords.db"):
        self.db_file = db_file
        self.connection = None
        self.create_table()

    def create_table(self):
        try:
            self.connection = sqlite3.connect(self.db_file)
            cursor = self.connection.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                              (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                              account TEXT NOT NULL,
                              username TEXT NOT NULL,
                              password_hash TEXT NOT NULL)''')
            self.connection.commit()
        except sqlite3.Error as e:
            print("Error creating table:", e)

    def close_connection(self):
        if self.connection:
            self.connection.close()

    def hash_password(self, password):
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return password_hash, salt

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for i in range(length))
        return password

    def store_password(self, account, username, password):
        try:
            password_hash, salt = self.hash_password(password)
            cursor = self.connection.cursor()
            cursor.execute('''INSERT INTO passwords (account, username, password_hash)
                              VALUES (?, ?, ?)''', (account, username, password_hash))
            self.connection.commit()
            print("Password stored successfully.")
        except sqlite3.Error as e:
            print("Error storing password:", e)

    def retrieve_password(self, account, username):
        try:
            cursor = self.connection.cursor()
            cursor.execute('''SELECT password_hash FROM passwords
                              WHERE account=? AND username=?''', (account, username))
            result = cursor.fetchone()
            if result:
                return result[0]
            else:
                print("Password not found for the specified account and username.")
        except sqlite3.Error as e:
            print("Error retrieving password:", e)

if __name__ == "__main__":
    password_manager = PasswordManager()

    # Example usage:
    password_manager.store_password("example.com", "user123", "password123")
    stored_password = password_manager.retrieve_password("example.com", "user123")
    print("Retrieved Password:", stored_password)

    password_manager.close_connection()
