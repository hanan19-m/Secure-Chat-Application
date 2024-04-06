import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import requests
import re
import tkinter as tk
from tkinter import scrolledtext
import threading
import datetime

# generate rsa key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

host = socket.gethostname()

# create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR , 1)
server_socket.bind((host, 1001))
server_socket.listen(1)

# accept connection from client
connection, client_address = server_socket.accept()
print('Client connected:', client_address)

# key exchange
connection.sendall(pem)
aes_key = connection.recv(32)
nonce = connection.recv(16)
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

    ######################


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


        response = requests.post(url_scan_endpoint, data=params)
        json_response = response.json()

        if response.status_code == 200 and json_response['response_code'] == 1:
            return 'Safe URL'
        else:
            return 'Unable to check URL safety'

    #########################

# Create the server chat window
server_chat_window = tk.Tk()
server_chat_window.geometry("400x400")
server_chat_window.title("Server Chat Page")



server_chat_text = scrolledtext.ScrolledText(server_chat_window, width=35, height=15)
server_chat_text.pack()
server_chat_window.withdraw()



def receive_message():
    while True:
        cipher_data = connection.recv(1024)
        if not cipher_data:
            break
        decrypted_message = decrypt(cipher_data)

        if decrypted_message == "LOGIN_SUCCESS":
            server_chat_window.deiconify()

        server_chat_text.insert(tk.END, f'Client: {decrypted_message}\n')
        server_chat_text.yview(tk.END)

        # Check if the received message contains any URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                          decrypted_message)


        for url in urls:
            url_safety = check_url_safety(url)

            server_chat_text.insert(tk.END,  f'URL SCANNER ({url_safety})' '\n')
            server_chat_text.yview(tk.END)


            api_key = 'bcad5ee3a00cd59fb7c08ab347c980b10ace61d578f40b871b5d8a2cc594a32a'
            report_endpoint = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={url}"
            report_response = requests.get(report_endpoint)
            report_data = report_response.json()

            # Print the scan report
            server_chat_text.insert(tk.END, f"Scan Report for {url}\n")
            if report_response.status_code == 200 and report_data['response_code'] == 1:
                server_chat_text.insert(tk.END, "Status: " + str(report_response.status_code) + '\n')
                server_chat_text.insert(tk.END, "Scan Date: " + report_data['scan_date'] + '\n')
                server_chat_text.insert(tk.END, "Positives: " + str(report_data['positives']) + '\n')
                server_chat_text.insert(tk.END, "Total: " + str(report_data['total']) + '\n')
            else:
                server_chat_text.insert(tk.END, "Unable to retrieve scan report\n")
                server_chat_text.yview(tk.END)



def send_message():


    plain_message = send_message_entry.get()
    connection.sendall(encrypt(plain_message))

    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    server_chat_text.insert(tk.END, f'you: {plain_message}  [{current_time}] \n')
    send_message_entry.delete(0, tk.END)
    server_chat_text.yview(tk.END)

send_message_entry = tk.Entry(server_chat_window, width=40)
send_message_entry.pack()


send_button = tk.Button(server_chat_window, text="Send", command=send_message)
send_button.pack()


receive_thread = threading.Thread(target=receive_message)
receive_thread.start()


server_chat_window.mainloop()