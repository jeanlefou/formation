import json
import socket

def reliable_send(socket_object,data):
    json_data = json.dumps(data)
    socket_object.send(json_data.encode())

def reliable_recv(socket_object):
    data = ''
    while True:
        try:
            data = data + socket_object.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue

def upload_file(socket_object,file_name):
    f = open(file_name, 'rb') #r=read, b=binary mode
    socket_object.send(f.read())

def download_file(socket_object,file_name):
    f = open(file_name, 'wb')
    socket_object.settimeout(2)
    chunk = socket_object.recv(1024)
    while chunk:
        f.write(chunk)
        try:
            chunk = socket_object.recv(1024)
        except socket.timeout as e:
            break
    socket_object.settimeout(None)
    f.close()