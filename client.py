#---------------------------------------------------------------------------------
#   Name:           John Carlo Salinas
#                   Gillian Florin
#   Course:         CPE 3151: Information Engineering
#   File Name:      SALINAS-FLORIN_client.py
#   Description:    a program for the client's end for a simple client-server
#                   application with applied public key encryption using RSA and
#                   message authentication through hashing using Sha256.
#----------------------------------------------------------------------------------
import socket
from threading import Thread
import rsa
import hashlib

c_publicKey, c_privateKey = rsa.newkeys(1024)
s_publicKey = ''
run = True

def enableRSA(conn):
    global run
    global c_publicKey
    global s_publicKey
    # share client public key
    clientPK_inPEM = rsa.PublicKey.save_pkcs1(c_publicKey, "PEM")
    conn.sendall(clientPK_inPEM)
    try:
        # receive and load client public key
        serverPK_inPEM = conn.recv(1024)
        s_publicKey = rsa.PublicKey.load_pkcs1(serverPK_inPEM, "PEM")
        print('SYSTEM: Encryption Enabled')
    # try catch exceptions
    except socket.error as err:
        print('SYSTEM: Connection Failed')
        run = False

def receiveMsg(conn):
    global run
    global c_privateKey
    while run:
        try:
            # instantiate hash object
            sha256 = hashlib.sha256()
            # receive server data
            msg = conn.recv(1024)
            if not msg:
                continue
            # apply private key decryption
            decryptedMsg = rsa.decrypt(msg, c_privateKey)
            # separate the hashedMsg from the plaintext msg
            rcvHashedMsg = decryptedMsg[:64]
            rcvMsg = decryptedMsg[64:]
            # hash the obtained plaintext msg for authentication
            sha256.update(rcvMsg)
            hashedRcvMsg = sha256.hexdigest()

            # message authentication
            if rcvHashedMsg.decode() == hashedRcvMsg:
                print('\nServer: {}'.format(rcvMsg.decode()))
            else:
                print('\nSYSTEM: detected malicious message upon reception.')

            print('Client: ')
        # try catch exceptions
        except socket.error as err:
            print('Server: {}'.format(msg.decode()))
            print('SYSTEM: Connection Failed')
            run = False
        except KeyboardInterrupt:
            run = False
    conn.close()

def sendMsg(conn):
    global run
    global s_publicKey
    while run:
        try:
            # instantiate hash object
            sha256 = hashlib.sha256()
            # send messsage to connected client
            msg = input("Client: ")
            # implement hash to message input
            sha256.update(msg.encode())
            hashedMsg = sha256.hexdigest()
            # concatenate hashedMsg + plaintext msg
            newMsg = hashedMsg + msg
            # apply public key encryption
            encryptedMsg = rsa.encrypt(newMsg.encode(), s_publicKey)
            conn.sendall(encryptedMsg)
            #if msg == 'exit':
            #    break
        # try catch exceptions
        except socket.error as err:
            print('SYSTEM: Connection Failed')
            run = False
        except KeyboardInterrupt:
            run = False
    conn.close() 

def establishConnection():
    # instantiates a socket in the session layer
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect client to server 127.0.0.1 port 8000
    conn.connect(('127.0.0.1', 8000))
    print('SYSTEM: Server Connection Established')
    return conn

if __name__ == '__main__':
    conn = establishConnection()
    enableRSA(conn)
    # receive message threading
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    # send message threading
    snd = Thread(target=sendMsg, args=(conn, ))
    snd.start()