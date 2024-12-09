#---------------------------------------------------------------------------------
#   Name:           John Carlo Salinas
#                   Gillian Florin
#   Course:         CPE 3151: Information Engineering
#   File Name:      SALINAS-FLORIN_server.py
#   Description:    a program for the server's end for a simple client-server
#                   application with applied public key encryption using RSA and
#                   message authentication through hashing using Sha256.
#----------------------------------------------------------------------------------
import socket
from threading import Thread
import rsa
import hashlib

s_publicKey, s_privateKey = rsa.newkeys(1024)
c_publicKey = ''
run = True

def enableRSA(conn):
    global run
    global s_publicKey
    global c_publicKey
    # share server public key
    serverPK_inPEM = rsa.PublicKey.save_pkcs1(s_publicKey, "PEM")
    conn.sendall(serverPK_inPEM)
    try:
        # receive and load client public key
        clientPK_inPEM = conn.recv(1024)
        c_publicKey = rsa.PublicKey.load_pkcs1(clientPK_inPEM, "PEM")
        print('SYSTEM: Encryption Enabled')
    # try catch exceptions
    except socket.error as err:
        print('SYSTEM: Connection Failed')
        run = False

def receiveMsg(conn):
    global run
    global s_privateKey
    while run:
        try:
            # instantiate hash object
            sha256 = hashlib.sha256()
            # receive client data
            msg = conn.recv(1024)
            if not msg:
                continue
            # apply private key decryption
            decryptedMsg = rsa.decrypt(msg, s_privateKey)
            # separate the hashedMsg from the plaintext msg
            rcvHashedMsg = decryptedMsg[:64]
            rcvMsg = decryptedMsg[64:]
            # hash the obtained plaintext msg for authentication
            sha256.update(rcvMsg)
            hashedRcvMsg = sha256.hexdigest()
            
            # message authentication
            if rcvHashedMsg.decode() == hashedRcvMsg:
                print('\nClient: {}'.format(rcvMsg.decode()))
            else:
                print('\nSYSTEM: detected malicious message upon reception.')

            print('Server: ')
        # try catch exceptions
        except socket.error as err:
            print('Client: {}'.format(msg.decode()))
            print('SYSTEM: Encryption Failed')
            run = False
        except KeyboardInterrupt:
            run = False
    conn.close()

def sendMsg(conn):
    global run
    global c_publicKey
    while run:
        try:
            # instantiate hash object
            sha256 = hashlib.sha256()
            # send messsage to connected client
            msg = input("Server: ")
            # implement hash to message input
            sha256.update(msg.encode())
            hashedMsg = sha256.hexdigest()
            # concatenate hashedMsg + plaintext msg
            newMsg = hashedMsg + msg
            # apply public key encryption
            encryptedMsg = rsa.encrypt(newMsg.encode(), c_publicKey)
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

def listenConnection():
    # instantiates a socket in the session layer
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # binds the socket to the address '127.0.0.1' and port 8000
    s.bind(('127.0.0.1', 8000))
    # listens for incomming connections; allow only 1 pending connection
    s.listen(1)
    # accept connection from client
    conn, addr = s.accept()
    print('SYSTEM: Client Connection Accepted')
    return conn, addr, s

if __name__ == '__main__':
    conn, addr, s = listenConnection()
    enableRSA(conn)
    # receive message threading
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    # send message threading
    snd = Thread(target=sendMsg, args=(conn, ))
    snd.start()