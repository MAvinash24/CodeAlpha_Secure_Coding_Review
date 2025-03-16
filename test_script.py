import sqlite3

password = "123456"
conn = sqlite3.connect('example.db')
cursor = conn.cursor()
user_input = input("Enter username: ")
cursor.execute("SELECT * FROM users WHERE username='" + user_input + "'")
exec("malicious_code")
from Crypto.Cipher import DES
cipher = DES.new(b'8bytekey', DES.MODE_ECB)

def risky_function():
    # Define the function here
    pass

try:
    risky_function()
except:
    pass
