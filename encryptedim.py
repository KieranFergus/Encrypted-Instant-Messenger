import argparse
import select
import socket
import sys
import signal
import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes


parser = argparse.ArgumentParser()
parser.add_argument("--s", action='store_true', help='wait for an incoming TCP/IP connection on port 9999')
parser.add_argument("--c", metavar="hostname", help='connect to the machine hostname (over TCP/IP on port 9999)')
parser.add_argument("--confkey", metavar="K1", required=True, help='encryption key to achieve confidentiality')
parser.add_argument("--authkey", metavar="K2", required=True, help='HMAC key to achieve authenticity')

args = parser.parse_args()

port = 9999

hostname = args.c
aes_key = SHA256.new(args.confkey.encode()).digest()
hmac_key = SHA256.new(args.authkey.encode()).digest()

def encrypt_data(data):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    data_bytes = data.encode()
    data_length = struct.pack("!I", len(data_bytes))
    length_enc = cipher.encrypt(data_length.ljust(16, b'\x00'))

    length_hmac = HMAC.new(hmac_key, iv + length_enc, SHA256).digest()

    padded_data = data_bytes.ljust((len(data_bytes) + 15) // 16 * 16, b'\x00')
    data_enc = cipher.encrypt(padded_data)

    data_hmac = HMAC.new(hmac_key, data_enc, SHA256).digest()

    return iv + length_enc + length_hmac + data_enc + data_hmac

def decrypt_data(ciphertext):
    iv = ciphertext[:16]
    ciphertext_length = ciphertext[16:32]
    received_length_hmac = ciphertext[32:64]

    length_hmac = HMAC.new(hmac_key, iv + ciphertext_length, SHA256).digest()
    if received_length_hmac != length_hmac:
        sys.stdout.write("ERROR: HMAC verification failed")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    length_ciph = cipher.decrypt(ciphertext_length).rstrip(b'\x00')
    length = struct.unpack("!I", length_ciph)[0]

    data_ciph = ciphertext[64:64 + length + (16 - (length % 16))]
    received_data_hmac = ciphertext[64 + len(data_ciph):]

    data_hmac = HMAC.new(hmac_key, data_ciph, SHA256).digest()
    if data_hmac != received_data_hmac:
        sys.stdout.write("ERROR: HMAC verification failed")

    message = cipher.decrypt(data_ciph).rstrip(b'\x00')
    return message.decode()




def boot_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', port)) 
    server.listen(5)
    conn, addr = server.accept()

    # def end(signum, frame):
    #     server.close()
    #     sys.exit(0)

    # signal.signal(signal.SIGINT, end)
    # signal.signal(signal.SIGTERM, end)

    try:
        while True:
            read, _, _ = select.select([conn, sys.stdin], [], [])

            incoming = ""

            for message in read:
                if message is conn:
                    incoming = conn.recv(4096)
                    sys.stdout.write(decrypt_data(incoming) + '\n')
                    sys.stdout.flush()
                elif message is sys.stdin:
                    outgoing = sys.stdin.readline().strip()                
                    conn.send(encrypt_data(outgoing))
                    sys.stdout.flush()

    except (EOFError, KeyboardInterrupt):
        x = 2
    finally:
        conn.close()
        server.close()
        sys.exit(0)
    



def boot_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((hostname, port))

    # def end(signum, frame):
    #     client.close()
    #     sys.exit(0)

    # signal.signal(signal.SIGINT, end)
    # signal.signal(signal.SIGTERM, end)

    try:
        while True:
            read, _, _ = select.select([client, sys.stdin], [], [])

            incoming = ""

            for message in read:
                if message is client:
                    incoming = client.recv(4096)
                    sys.stdout.write(decrypt_data(incoming) + '\n')
                    sys.stdout.flush()
                elif message is sys.stdin:
                    outgoing = sys.stdin.readline().strip()
                    client.sendall(encrypt_data(outgoing))
                    sys.stdout.flush()

    except (EOFError, KeyboardInterrupt):
        x = 2
    finally:
        client.close()
        sys.exit(0)



if args.s:
    boot_server()
elif args.c:
    boot_client()



