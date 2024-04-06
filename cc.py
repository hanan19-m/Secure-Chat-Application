import os
import sqlite3
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
import hashlib
import re
import requests
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from threading import Thread
from queue import Queue
import datetime




main_window = tk.Tk()
main_window.title("sign in")
main_window.geometry("400x400")


username_label = tk.Label(main_window, text="Username:")
username_label.pack()
username_entry = tk.Entry(main_window)
username_entry.pack()

password_label = tk.Label(main_window, text="Password:")
password_label.pack()
password_entry = tk.Entry(main_window, show="*")
password_entry.pack()



host = socket.gethostname()
signed_in = False




conn = sqlite3.connect('user_database.db')
cursor = conn.cursor()

# Create the users table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT
                )''')


# connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, 1001))



# key exchange
server_public_key = load_pem_public_key(client_socket.recv(1024))
aes_key = os.urandom(32)
nonce = os.urandom(16)
client_socket.sendall(aes_key)
client_socket.sendall(nonce)
cipher = Cipher(algorithms.AES256(aes_key), modes.CTR(nonce))


def encrypt(string):
    encryptor = cipher.encryptor()
    data = bytes(string, 'utf-8')
    data = append_hash(data)
    return encryptor.update(data) + encryptor.finalize()


def decrypt(data):
    decryptor = cipher.decryptor()
    byte_slice = decryptor.update(data) + decryptor.finalize()
    if not verify_hash(byte_slice):
        print("invalid hash")
        exit(1)
    return str(byte_slice[:-32], 'utf-8')


def append_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    return data + bytes(hash_value)


def verify_hash(data):
    message = data[:-32]
    append_hash = data[-32:]
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash = digest.finalize()
    return append_hash == hash


def check_url_safety(url):
    # Enter your VirusTotal API key here
    api_key = 'bcad5ee3a00cd59fb7c08ab347c980b10ace61d578f40b871b5d8a2cc594a32a'

    # VirusTotal API endpoint for URL scanning
    url_scan_endpoint = 'https://www.virustotal.com/vtapi/v2/url/scan'

    # Parameters for the API request
    params = {
        'apikey': api_key,
        'url': url
    }

    # Send the URL to the VirusTotal API for scanning
    response = requests.post(url_scan_endpoint, data=params)
    json_response = response.json()

    # Check the scan response
    if response.status_code == 200 and json_response['response_code'] == 1:
        # If the API response is successful, the URL scan should have been initiated
        return 'Safe URL'
    else:
        return 'Unable to check URL safety'


# Create the login button
def login_user():
    username = username_entry.get()
    password = password_entry.get()

    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()

    if user is None:
        messagebox.showerror("Error", "Username does not exist. Please sign up first.")
        return

    stored_password = user[1]
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if hashed_password == stored_password:
        messagebox.showinfo("Success", "Welcome, {}! You have signed in successfully.".format(username))

        main_window.destroy()  # Close the sign-in window


        chat_window = tk.Tk()
        chat_window.title("Chat Page")


        chat_text = tk.Text(chat_window)
        chat_text.pack()


        def send_message():
            message = input_entry.get()
            current_time = datetime.datetime.now().strftime("%H:%M:%S")
            message_with_time = f'{message} [{current_time}]\n'

            chat_text.insert(tk.END, "You: " + message_with_time + "\n")
            message_queue.put(message_with_time)  # Put the message into the queue


            input_entry.delete(0, tk.END)




        def communication_thread():
            while True:
                message = message_queue.get()
                client_socket.sendall(encrypt(message))
                cipher_data = client_socket.recv(1024)
                decrypted_message = decrypt(cipher_data)
                #print('Server:', decrypted_message)

                current_time = datetime.datetime.now().strftime("%H:%M:%S")
                chat_window.after(0,
                                  lambda: chat_text.insert(tk.END, f'Server: {decrypted_message} [{current_time}] \n'))

                process_message(decrypted_message)





        def process_message(message):

            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                              message)


            for url in urls:
                url_safety = check_url_safety(url)
                checked_message = f'URL SCANNER: ({url_safety})'
                chat_text.insert(tk.END, checked_message + "\n")

        input_entry = tk.Entry(chat_window)
        input_entry.pack()

        send_button = tk.Button(chat_window, text="Send", command=send_message)
        send_button.pack()

        message_queue = Queue()

        communication_thread = Thread(target=communication_thread)
        communication_thread.daemon = True
        communication_thread.start()

        chat_window.mainloop()
    else:

        messagebox.showerror("Error", "Incorrect password. Please try again.")


login_button = tk.Button(main_window, text="Sign In", command=login_user)


signup_link = tk.Label(main_window, text="Don't have an account? Sign Up", fg="blue", cursor="hand2")
signup_link.pack()


def show_signup_page(event):

    username_label.pack_forget()
    username_entry.pack_forget()
    password_label.pack_forget()
    password_entry.pack_forget()
    login_button.pack_forget()
    signin_link.pack_forget()

    signup_label.pack()
    username_label.pack()
    signup_username_entry.pack()
    signup_password_label.pack()
    signup_password_entry.pack()
    signup_button.pack()


    signin_link.pack()

signup_link.bind("<Button-1>", show_signup_page)



signup_label = tk.Label(main_window, text="Sign Up")
signup_username_entry = tk.Entry(main_window)
signup_password_label = tk.Label(main_window, text="Password:")
signup_password_entry = tk.Entry(main_window, show="*")

def signup_user():
    username = username_entry.get()
    password = password_entry.get()

    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    if cursor.fetchone() is not None:
        messagebox.showerror("Error", "Username already exists. Please choose a different username.")
        return
    else:

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        cursor.execute('INSERT INTO users VALUES (?, ?)', (username, hashed_password))
        conn.commit()

        messagebox.showinfo("You have signed up successfully.")
        show_signin_page()

def show_signin_page():
    signup_label.pack_forget()
    signup_username_entry.pack_forget()
    signup_password_label.pack_forget()
    signup_password_entry.pack_forget()
    signup_button.pack_forget()

    signin_label.pack()
    username_label.pack()
    username_entry.pack()
    password_label.pack()
    password_entry.pack()
    login_button.pack()
    signin_link.pack()

signin_label = tk.Label(main_window, text="Sign in")

signup_button = tk.Button(main_window, text="Sign Up", command=signup_user)

signin_link = tk.Label(main_window, text="Already have an account? Sign In", fg="blue", cursor="hand2")



def show_signin_page(event):

    signup_label.pack_forget()
    signup_username_entry.pack_forget()
    signup_password_label.pack_forget()
    signup_password_entry.pack_forget()
    signup_button.pack_forget()


    username_label.pack()
    username_entry.pack()
    password_label.pack()
    password_entry.pack()
    login_button.pack()


    signup_link.pack()

signin_link.bind("<Button-1>", show_signin_page)


username_label.pack()
username_entry.pack()
password_label.pack()
password_entry.pack()
login_button.pack()
signup_link.pack()


main_window.mainloop()


conn.close()


client_socket.close()