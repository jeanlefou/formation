import json

def reliable_send(target,data):
    json_data = json.dumps(data)
    target.send(json_data.encode())

def reliable_recv(target):
    data = ''
    while True:
        try:
            data = data + target.recv(1024).decode().rstip()
            #1024 : number of bytes to receive
            #decode
            #estip
            return json.loads(data)
        except ValueError:
            continue
