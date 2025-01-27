import argparse
import select
import socket
import sys
import signal


parser = argparse.ArgumentParser()
parser.add_argument("--s", action='store_true', help='wait for an incoming TCP/IP connection on port 9999')
parser.add_argument("--c", metavar="hostname", help='connect to the machine hostname (over TCP/IP on port 9999)')

args = parser.parse_args()

port = 9999
hostname = args.c


def boot_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', port)) 
    server.listen(5)
    conn, addr = server.accept()

    def end(signum, frame):
        server.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, end)
    signal.signal(signal.SIGTERM, end)

    while True:
        read, _, _ = select.select([conn, sys.stdin], [], [])

        incoming = ""

        for message in read:
            if message is conn:
                incoming += conn.recv(1024).decode()
                sys.stdout.write(incoming)
                sys.stdout.flush()
            elif message is sys.stdin:
                outgoing = sys.stdin.readline().strip()                
                conn.send((outgoing + '\n').encode())
                sys.stdout.flush()
    



def boot_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((hostname, port))

    def end(signum, frame):
        client.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, end)
    signal.signal(signal.SIGTERM, end)

    while True:
        read, _, _ = select.select([client, sys.stdin], [], [])

        incoming = ""

        for message in read:
            if message is client:
                incoming += client.recv(1024).decode()
                sys.stdout.write(incoming)
                sys.stdout.flush()
            elif message is sys.stdin:
                outgoing = sys.stdin.readline().strip()
                client.sendall((outgoing + '\n').encode())
                sys.stdout.flush()
        



if args.s:
    boot_server()
elif args.c:
    boot_client()



