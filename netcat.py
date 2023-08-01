#!/usr/bin/env python3
"""Python netcat implementation."""
#import libraries

import argparse
import os
import re
import socket
import sys
import threading
import hmac as HMAC
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac,hashes
from cryptography.hazmat.primitives.serialization import *
import binascii as ba
import socketserver
import sys

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util import Counter
from Crypto import Random
from binascii import hexlify

# -------------------------------------------------------------------------------------------------
# GLOBALS
# -------------------------------------------------------------------------------------------------

# In case the server is running in UDP mode
# it must wait for the client to connect in order
# to retrieve its addr and port in order to be able
# to send data back to it.
UDP_CLIENT_ADDR = None
UDP_CLIENT_PORT = None

NAME = os.path.basename(sys.argv[0])
VERSION = "0.1.0-alpha"

#AES_key = ("Network Security").encode('utf-8')
iv = ("1234"*4).encode('utf-8')
salt_session_key = b''
mac_key = b''
# -------------------------------------------------------------------------------------------------
# Symmetric Encrypt algorithm needed
# -------------------------------------------------------------------------------------------------
#Apply padding
#buffer size = 32
def pad(s, bs=32):
    return bytes(s + (16 - len(s) % 16) * chr(16 - len(s) % 16), 'utf-8')

def unpad(s):
        return s[0:-ord(s[-1:])]
    

def encryption(key, raw, mode):
    data = pad(raw)
    # if mode != AES.MODE_CTR and mode != AES.MODE_ECB:
    #     cipher = AES.new(key,mode,iv)
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
    # else:
    #     cipher = AES.new(key,AES.MODE_CTR,counter=ctr_encrypt_counter)
        
    return cipher.encrypt(data)

def decryption(key, ctext, mode):
    # if mode != AES.MODE_CTR and mode != AES.MODE_ECB:       
    #     cipher = AES.new(key,mode,iv)
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
    # else:
    #     cipher = AES.new(key,AES.MODE_CTR,counter=ctr_decrypt_counter)
        
    return unpad(cipher.decrypt(ctext))  

def compute_hmac(message, key):
    return HMAC.new(key, message, hashlib.sha256).digest()

# -------------------------------------------------------------------------------------------------
#generate DH parameters and DH key
# -------------------------------------------------------------------------------------------------
def generate_dh_params():
    print('Generating dh parameters')
    params = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
    print('Parameters have been generated, Server is ready for requests ...')
    return params

def generate_dh_prvkey(params):
    '''
    Generate a random private key (and a public key) from DH parameters
    '''
    print(params.generate_private_key())
    return params.generate_private_key()


def check_client_pubkey(pubkey):
    '''
    Check whether the client public key is a valid instance of DH
    shouldn't we check whether the key is valid under the parameters
    sent by the server?
    '''
    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False

# -------------------------------------------------------------------------------------------------
#Overwirte Dh_Server_Handler (For Server！)
# -------------------------------------------------------------------------------------------------

def DH_Server_Handler(sock):
    global salt_session_key
    global mac_key
    params = generate_dh_params()
    state = 0

    data = sock.recv(3072).strip()

    if state == 0 and data == b'Hello':
        state = 1
        print(data, state)
        response = b'Hey there!'
        sock.sendall(response)
    else:
        response = b'I do not understand you, hanging up'
        sock.sendall(response)
        return

    data = sock.recv(3072).strip()

    if state == 1 and data == b'Params?':
        state = 2
        print(data, state)
        dh_params = params
        response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
        sock.sendall(response)
    else:
        response = b'I do not understand you, hanging up'
        sock.sendall(response)
        return

    data = sock.recv(3072).strip()

    if state == 2 and bytearray(data)[0:18] == b'Client public key:':
        client_pubkey = load_pem_public_key(bytes(bytearray(data)[18:]), default_backend())
        if client_pubkey:
            server_keypair = generate_dh_prvkey(params)
            response = b'Server public key:' + server_keypair.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            shared_secret = server_keypair.exchange(client_pubkey)
            state = 0
            print(data, state)
            sock.sendall(response)
            print('Shared Secret:\n{}'.format(ba.hexlify(shared_secret)))


            rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            rsa_private_key_bytes = rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            print('Server Rsa private key:\n{}' + rsa_private_key_bytes.decode('utf-8'))
            rsa_public_key = rsa_private_key.public_key()
            response = b'Server Rsa public key:' +  rsa_public_key.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            sock.sendall(response)
            rsa_public_key_bytes = rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print('Server Rsa public key:\n{}'+ rsa_private_key_bytes.decode('utf-8'))
            state = 3
        else:
        # if we get here the client key is not right
            response = b'Invalid client public key, hanging up'
            sock.sendall(response)
            return
    data = sock.recv(3072).strip()
    if state == 3 and bytearray(data)[0:16] == b'Encrypt salt is:':
        encrypt_salt = bytes(bytearray(data)[16:])
        print('Encrypt salt:\n{}'.format(encrypt_salt))
        salt = rsa_private_key.decrypt(
            encrypt_salt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print('random salt + mac_key is:\n{}'.format(salt))
        session_salt = salt[:32]
        print('salt is:\n{}'.format(session_salt))
        mac_key = salt[32:]
        print('mac_key is:\n{}'.format(mac_key))
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 使用32字节的密钥长度
            salt=session_salt,  # 使用双方约定的盐值
            iterations= 100
        )
        salt_session_key = kdf.derive(shared_secret)
        print('salt session key:\n{}'.format(salt_session_key))
        #plaintext is a character string of 5 blocks of 16 bytes 
        plaintext = "Monash_FIT3031**"*5

        print("Plaintext")
        print(plaintext)

        ciphertext= encryption(salt_session_key,plaintext,AES.MODE_ECB)

        print("Ciphertext in hex mode")
        print(ciphertext)

        response = ciphertext
        sock.sendall(response)  #sent the ciphertext to client

        # content= decryption(k,ciphertext,iv,AES.MODE_ECB).decode("utf-8")
        # print("Content after decryption")
        # print(content)
        return
    else:
        print("salt exchange went wrong")
        return
# -------------------------------------------------------------------------------------------------
#Overwirte Dh_Client_Handler (For Client！)
#define a DH_Client_Handler class to handle the pre-connection work
# -------------------------------------------------------------------------------------------------

def DH_Client_Handler(sock):
    global salt_session_key
    global mac_key
    # Set the first request according to our protocol
    request = b'Hello'
    # Send the request
    sock.sendall(request)
    # Read the server's response
    received = sock.recv(3072).strip()
    # Print what we have received from the server
    print('Received:\n{}'.format(received))
    # Check if the response is valid acording to our protocol
    if received == b'Hey there!':
        # Set the next request accordingly
        request = b'Params?'
        sock.sendall(request)
    else:
        # If we get here something is not right
        print('Bad response')
        # Close the connection and return
        sock.close()
        return

    # This means we are still in the game and the next server response must be the DH parameters
    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    dh_params = load_pem_parameters(received, default_backend())
    # Check if the params are valid DH params
    if isinstance(dh_params, dh.DHParameters):
        # Based on received parameters we generate a key pair
        client_keypair = dh_params.generate_private_key()
        # Create the next message according to the protocol, get the binary of the public key
        # to send to the server
        request = b'Client public key:' + client_keypair.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        sock.sendall(request)
    else:
        print('Bad response')
        sock.close()
        return

    # This means we are still in the game
    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    # Check the format of the message (or rather the beginning)
    if bytearray(received)[0:18] == b'Server public key:':
        # Get the server's public key from the binary and its proper index to the end
        server_pubkey = load_pem_public_key(bytes(bytearray(received)[18:]), default_backend())
        if isinstance(server_pubkey, dh.DHPublicKey):
            # Calculate the shared secret
            shared_secret = client_keypair.exchange(server_pubkey)
            # Print the shared secret
            print('Shared Secret\n{}'.format(ba.hexlify(shared_secret)))

            iv = ("1234"*4).encode('utf-8')

    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    if bytearray(received)[0:22] == b'Server Rsa public key:':
        server_rsa_pubkey = load_pem_public_key(bytes(bytearray(received)[22:]), default_backend())
        salt = os.urandom(64)
        print('random salt + mac_key is:\n{}'.format(salt))
        session_salt = salt[:32]
        print('salt is:\n{}'.format(session_salt))
        mac_key = salt[32:]
        print('mac_key is:\n{}'.format(mac_key))
        encrypted_salt = server_rsa_pubkey.encrypt(
            salt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print('Encrypt salt is:\n{}'.format(encrypted_salt))
        sock.sendall(b'Encrypt salt is:' + encrypted_salt)


        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
            length=32,  # 使用32字节的密钥长度
            salt=session_salt,  # 使用双方约定的盐值
            iterations= 100
        )
        salt_session_key = kdf.derive(shared_secret)
        print('salt session key:\n{}'.format(salt_session_key))

        # Received and decode the cipher text
        received = sock.recv(3072).strip()
        print('Received:\n{}'.format(received))
        ciphertext = received

        content = decryption(salt_session_key, ciphertext, AES.MODE_ECB).decode("utf-8")
        print("Message after decryption")
        print(content)
        return  

    # If we get here it means something went wrong
    print('Failed')
    sock.close()
    return
# -------------------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------------------------------------


def b2str(data):
    """Convert bytes into string type."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def log(msg, level, verbose):
    """Log messages to stderr."""
    if level == "error":
        print("%s" % (msg), file=sys.stderr)
    elif level == "warning":
        print("%s" % (msg), file=sys.stderr)
    elif level == "info" and verbose > 0:
        print("%s" % (msg), file=sys.stderr)
    elif level == "debubg:" and verbose > 1:
        print("%s" % (msg), file=sys.stderr)
    else:
        print("Fatal, wrong logging level: '%s'. Please report this issue", file=sys.stderr)
        sys.exit(1)


# -------------------------------------------------------------------------------------------------
# CLIENT/SERVER COMMUNICATOIN FUNCTIONS
# -------------------------------------------------------------------------------------------------


def send(s, udp=False, crlf=False, verbose=0):
    global salt_session_key
    global mac_key
    """Send one newline terminated line to a connected socket."""
    # In case of sending data back to an udp client we need to wait
    # until the client has first connected and told us its addr/port
    if udp and UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
        while UDP_CLIENT_ADDR is None and UDP_CLIENT_PORT is None:
            pass
        if verbose > 0:
            print("Client:     %s:%i" % (UDP_CLIENT_ADDR, UDP_CLIENT_PORT), file=sys.stderr)

    # Loop for the thread
    while True:
        # Read user input
        data = input()

        # Ensure to terminate with desired newline
        if isinstance(data, bytes):
            data = b2str(data)
        if crlf:
            data += "\r\n"
        else:
            data += "\n"

        # data = data.encode("utf-8")
        # hmac_value = compute_hmac(data,mac_key)
        # message_with_hmac = hmac_value + data
        # message_with_hmac = message_with_hmac.hex()
        #encrypt here!
        encrypt_data = encryption(salt_session_key,data,AES.MODE_ECB)
        print('encrypt_data:\n{}'.format(encrypt_data))
        mac = HMAC.new(mac_key, digestmod=hashlib.sha256)
        mac.update(encrypt_data)
        calculate_mac = mac.digest()
        encryptdata_with_mac = calculate_mac + encrypt_data
        print('encryptdata_with_mac\n{}'.format(encryptdata_with_mac))

        size = len(encryptdata_with_mac)
        print("encryptdata_with_mac type: ",type(encryptdata_with_mac))
        send = 0

        # Loop until all bytes have been send
        while send < size:
            try:
                if udp:
                    send += s.sendto(encryptdata_with_mac, (UDP_CLIENT_ADDR, UDP_CLIENT_PORT))
                else:
                    send += s.send(encryptdata_with_mac)
            except (OSError, socket.error) as error:
                print("[Send Error] %s" % (error), file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                # exit the thread
                return

    # Close connection when thread stops
    s.close()


def receive(s, udp=False, bufsize=1024, verbose=0):
    """Read one newline terminated line from a connected socket."""
    global salt_session_key
    global mac_key
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

    if verbose > 0:
        print("Receiving:  bufsize=%i" % (bufsize), file=sys.stderr)

    # Loop for the thread
    while True:

        rec_byte = b""
        size = len(rec_byte)

        while True:
            try:
                (rec_byte, addr) = s.recvfrom(bufsize)
                #rec_byte += bytes(byte)
                received_mac = rec_byte[:32]  # Extract the MAC from the digest_data
                received_data = rec_byte[32:]  # Extract the data from the digest_data
                print('received_mac:\n{}'.format(received_mac))
                print('received_data:\n{}'.format(received_data))
                    #MAC authentication
                mac = HMAC.new(mac_key, digestmod=hashlib.sha256)
                mac.update(received_data)
                clculate_mac = mac.digest()
                if clculate_mac != received_mac:
                    print("MAC failed")
                    return

                decrypt_data = decryption(salt_session_key,received_data,AES.MODE_ECB)
                print('decrypt_data:\n{}'.format(decrypt_data))
                decrypt_data = b2str(decrypt_data)
                #decrypt data here
                #decrypt_data = decryption(salt_session_key,rec_byte,AES.MODE_ECB)
                # Verify the MAC and recover the original data

                #received_data = b2str(received_data)
                #decrypt_data = received_data.decode("utf-8")
                if udp:
                    UDP_CLIENT_ADDR, UDP_CLIENT_PORT = addr

            except socket.error as err:
                print(err, file=sys.stderr)
                print(s, file=sys.stderr)
                s.close()
                sys.exit(1)


            if not decrypt_data:
                if verbose > 0:
                    print("[Receive Error] Upstream connection is gone", file=sys.stderr)
                s.close()
                # exit the thread
                return
            # Newline terminates the read request
            if decrypt_data.endswith("\n"):
                break
            # Sometimes a newline is missing at the end
            # If this round has the same data length as previous, we're done
            if size == len(decrypt_data):
                break
            size = len(decrypt_data)


        # Remove trailing newlines
        decrypt_data = decrypt_data.rstrip("\r\n")
        decrypt_data = decrypt_data.rstrip("\n")
        if verbose > 0:
            print("< ", end="", flush=True, file=sys.stderr)
        print(decrypt_data)

    # Close connection when thread stops
    s.close()


# -------------------------------------------------------------------------------------------------
# CLIENT/SERVER INITIALIZATION FUNCTIONS
# -------------------------------------------------------------------------------------------------

#
# Server/Client (TCP+UDP)
#
def create_socket(udp=False, verbose=0):
    """Create TCP or UDP socket."""
    try:
        if udp:
            if verbose > 0:
                print("Socket:     UDP", file=sys.stderr)
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            if verbose > 0:
                print("Socket:     TCP", file=sys.stderr)
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as error:
        print("[Socker Error] %s", (error), file=sys.stderr)
        sys.exit(1)


#
# Server (TCP+UDP)
#
def bind(s, host, port, verbose=0):
    """Bind TCP or UDP socket to host/port."""
    if verbose > 0:
        print("Binding:    %s:%i" % (host, port), file=sys.stderr)
    try:
        s.bind((host, port))
    except (OverflowError, OSError, socket.error) as error:
        print("[Bind Error] %s" % (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


#
# Server (TCP only)
#
def listen(s, backlog=1, verbose=0):
    """Make TCP socket listen."""
    try:
        if verbose > 0:
            print("Listening:  backlog=%i" % (backlog), file=sys.stderr)
        s.listen(backlog)
    except socket.error as error:
        print("[Listen Error] %s", (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


#
# Server (TCP only)
#
def accept(s, verbose=0):
    """Accept connections on TCP socket."""
    try:
        c, addr = s.accept()
    except (socket.gaierror, socket.error) as error:
        print("[Accept Error] %s", (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)

    host, port = addr
    if verbose > 0:
        print("Client:     %s:%i" % (host, port), file=sys.stderr)

    return c


#
# Client (TCP+UDP)
#
def resolve(hostname, verbose=0):
    """Resolve hostname to IP addr or return False in case of error."""
    if verbose > 0:
        print("Resolving:  %s" % (hostname), file=sys.stderr)
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as error:
        print("[Resolve Error] %s" % (error), file=sys.stderr)
        return False


#
# Client (TCP+UDP)
#
def connect(s, addr, port, verbose=0):
    """Connect to a server via IP addr/port."""
    if verbose > 0:
        print("Connecting: %s:%i" % (addr, port), file=sys.stderr)
    try:
        s.connect((addr, port))
    except socket.error as error:
        print("[Connect Error] %s" % (error), file=sys.stderr)
        print(s, file=sys.stderr)
        s.close()
        sys.exit(1)


# -------------------------------------------------------------------------------------------------
# CLIENT
# -------------------------------------------------------------------------------------------------


def run_client(host, port, udp=False, bufsize=1024, crlf=False, verbose=0):
    """Connect to host:port and send data."""
    global Shared_AES_key
    global UDP_CLIENT_ADDR
    global UDP_CLIENT_PORT

    s = create_socket(udp=udp, verbose=verbose)

    addr = resolve(host, verbose=verbose)
    #return the address of hostname
    if not addr:
        s.close()
        sys.exit(1)

    if udp:
        UDP_CLIENT_ADDR = addr
        UDP_CLIENT_PORT = port
    else:
        connect(s, addr, port, verbose=verbose)

    #add the key_exchange function
    DH_Client_Handler(s)

    # Start sending and receiving threads 
    # Multe thread at the same time
    tr = threading.Thread(
        target=receive, args=(s,), kwargs={"udp": udp, "bufsize": bufsize, "verbose": verbose}
    )
    ts = threading.Thread(
        target=send, args=(s,), kwargs={"udp": udp, "crlf": crlf, "verbose": verbose}
    )
    # If the main thread kills, this thread will be killed too.
    tr.daemon = True
    ts.daemon = True
    # Start threads
    tr.start()
    ts.start()

    # Do cleanup on the main program
    while True:
        if not tr.is_alive():
            s.close()
            sys.exit(0)
        if not ts.is_alive():
            s.close()
            sys.exit(0)


# -------------------------------------------------------------------------------------------------
# SERVER
# -------------------------------------------------------------------------------------------------


def run_server(host, port, udp=False, backlog=1, bufsize=1024, crlf=False, verbose=0):
    """Start TCP/UDP server on host/port and wait endlessly to sent/receive data."""
    global Shared_AES_key
    s = create_socket(udp=udp, verbose=verbose)

    bind(s, host, port, verbose=verbose)

    if not udp:
        listen(s, backlog=backlog, verbose=verbose)
        c = accept(s, verbose=verbose)
    else:
        c = s
    #add the server pre_connection function
    DH_Server_Handler(c)

    # start sending and receiving threads
    tr = threading.Thread(
        target=receive, args=(c,), kwargs={"udp": udp, "bufsize": bufsize, "verbose": verbose}
    )
    ts = threading.Thread(
        target=send, args=(c,), kwargs={"udp": udp, "crlf": crlf, "verbose": verbose}
    )
    # if the main thread kills, this thread will be killed too.
    tr.daemon = True
    ts.daemon = True
    # start threads
    tr.start()
    ts.start()

    # do cleanup on the main program
    while True:
        if not tr.is_alive():
            c.close()
            s.close()
            sys.exit(0)
        if not ts.is_alive():
            c.close()
            s.close()
            sys.exit(0)


# -------------------------------------------------------------------------------------------------
# COMMAND LINE ARGUMENTS
# -------------------------------------------------------------------------------------------------


def get_version():
    """Return version information."""
    return """%(prog)s: Version %(version)s (%(url)s) by %(author)s""" % (
        {
            "prog": NAME,
            "version": VERSION,
            "url": "https://github.com/cytopia/netcat",
            "author": "cytopia",
        }
    )


def _args_check_port(value):
    """Check arguments for invalid port number."""
    min_port = 1
    max_port = 65535
    intvalue = int(value)

    if intvalue < min_port or intvalue > max_port:
        raise argparse.ArgumentTypeError("%s is an invalid port number." % value)
    return intvalue


def _args_check_forwards(value):
    """Check forward argument (-L/-R) for correct pattern."""
    match = re.search(r"(.+):(.+)", value)
    if match is None or len(match.groups()) != 2:
        raise argparse.ArgumentTypeError("%s is not a valid 'addr:port' format." % value)
    _args_check_port(match.group(2))
    return value


def get_args():
    """Retrieve command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage="""%(prog)s [-Cnuv] [-e cmd] hostname port
       %(prog)s [-Cnuv] [-e cmd] -l [hostname] port
       %(prog)s [-Cnuv] -L addr:port [hostname] port
       %(prog)s [-Cnuv] -R addr:port hostname port
       %(prog)s -V, --version
       %(prog)s -h, --help
       """
        % ({"prog": NAME}),
        description="Netcat implementation in Python with connect, listen and forward mode.",
        epilog="""examples:

  Create bind shell
    %(prog)s -l -e '/bin/bash' 8080

  Create reverse shell
    %(prog)s -e '/bin/bash' example.com 4444

  Local forward: Make localhost port available to another interface
    %(prog)s -L 127.0.0.1:3306 192.168.0.1 3306

  Remote forward: Forward local port to remote server
    %(prog)s -R 127.0.0.1:3306 example.com 4444"""
        % ({"prog": NAME}),
    )

    positional = parser.add_argument_group("positional arguments")
    mode = parser.add_argument_group("mode arguments")
    optional = parser.add_argument_group("optional arguments")
    misc = parser.add_argument_group("misc arguments")

    positional.add_argument(
        "hostname", nargs="?", type=str, help="Address to listen, forward or connect to"
    )
    positional.add_argument(
        "port", type=_args_check_port, help="Port to listen, forward or connect to"
    )

    mode.add_argument(
        "-l",
        "--listen",
        action="store_true",
        help="Listen mode: Enable listen mode for inbound connects",
    )
    mode.add_argument(
        "-L",
        "--local",
        metavar="addr:port",
        type=_args_check_forwards,
        help="""Local forward mode: Specify local <addr>:<port> to which traffic
should be forwarded to.
Netcat will listen locally (specified by hostname and port) and
forward all traffic to the specified value for -L/--local.""",
    )
    mode.add_argument(
        "-R",
        "--remote",
        metavar="addr:port",
        type=_args_check_forwards,
        help="""Remote forward mode: Specify local <addr>:<port> from which traffic
should be forwarded from.
Netcat will connect remotely (specified by hostname and port) and
for ward all traffic from the specified value for -R/--remote.""",
    )

    optional.add_argument(
        "-e",
        "--exec",
        metavar="cmd",
        type=str,
        help="Execute shell command. Only works with connect or listen mode.",
    )
    optional.add_argument(
        "-C", "--crlf", action="store_true", help="Send CRLF as line-endings (default: LF)",
    )
    optional.add_argument(
        "-n", "--nodns", action="store_true", help="Do not resolve DNS",
    )
    optional.add_argument("-u", "--udp", action="store_true", help="UDP mode")
    optional.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Be verbose and print info to stderr. Use -vv or -vvv for more verbosity.",
    )
    misc.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    misc.add_argument(
        "-V",
        "--version",
        action="version",
        version=get_version(),
        help="Show version information and exit",
    )
    args = parser.parse_args()

    # Check mutually exclive arguments
    if args.exec is not None and (args.local is not None or args.remote is not None):
        parser.print_usage()
        print(
            "%s: error: -e/--cmd cannot be used together with -L/--local or -R/--remote" % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)
    if args.listen and (args.local is not None or args.remote is not None):
        parser.print_usage()
        print(
            "%s: error: -l/--listen cannot be used together with -L/--local or -R/--remote"
            % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)
    if args.local is not None and args.remote is not None:
        parser.print_usage()
        print(
            "%s: error: -L/--local cannot be used together with -R/--remote" % (NAME),
            file=sys.stderr,
        )
        sys.exit(1)

    # Required arguments
    if args.hostname is None and (not args.listen and args.local is None):
        parser.print_usage()
        print(
            "%s: error: the following arguments are required: hostname" % (NAME), file=sys.stderr,
        )
        sys.exit(1)

    return args


# -------------------------------------------------------------------------------------------------
# MAIN ENTRYPOINT
# -------------------------------------------------------------------------------------------------


def main():
    """Start the program."""
    args = get_args()

    listen_backlog = 1
    receive_buffer = 1024
    hostname = args.hostname if args.hostname is not None else "0.0.0.0"

    if args.listen:
        run_server(
            hostname,
            args.port,
            args.udp,
            backlog=listen_backlog,
            bufsize=receive_buffer,
            crlf=args.crlf,
            verbose=args.verbose,
        )
    else:
        run_client(
            args.hostname,
            args.port,
            args.udp,
            bufsize=receive_buffer,
            crlf=args.crlf,
            verbose=args.verbose,
        )


if __name__ == "__main__":
    # Catch Ctrl+c and exit without error message
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(1)
