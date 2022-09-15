import json

def reliable_send(socket,data):
    json_data = json.dumps(data)
    socket.send(json_data.encode())

def reliable_recv(socket):
    data = ''
    while True:
        try:
            data = data + socket.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue
