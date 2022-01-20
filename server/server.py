'Chat Room Connection - Client-To-Client'

import threading
import socket
import time

host = '127.0.0.1'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
clients = []
aliases = []
public_keys = []

def broadcast(message):
    for client in clients:  
        client.send(message)

# Function to handle clients'connections

def handle_client(client):
    while True:
        try:
            input_message = client.recv(32767)
            try:
                message = input_message.decode("utf-8")
                print(message)
                if message.split(':')[0] == "pub_key":
                    index = clients.index(client)
                    key =  message.split(':')[1].encode("utf-8")
                    public_keys[index] = key
                    output = b''.join([b'server-pub_key:',aliases[index],b':',public_keys[index]])
                    time.sleep(5)
                    broadcast(output)
                    if(index != 0):
                        output = b''.join([b'server-pub_key:',aliases[0],b':',public_keys[0]])
                        broadcast(output)
                elif message == "EXIT":
                    remove_client(client)
                    break
                else:
                    broadcast(message.encode("utf-8"))
            except:
                print("execept : ",input_message)
                broadcast(input_message)
        except:
            remove_client(client)
            break
        
# Main function to receive the clients connection


def receive():
    while True:
        print('Server is running and listening ...')
        client, address = server.accept()
        print(f'connection is established with {str(address)}')
        client.send('alias?'.encode('utf-8'))
        alias = client.recv(32767)
        aliases.append(alias)
        clients.append(client)
        public_keys.append(str(clients.index(client)))
        print(f'The alias of this client is {alias}')
        msg= b''.join([alias,b' has connected to the chat room'])
        broadcast(msg)
        client.send(' ,you are now connected!'.encode('utf-8'))
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

def remove_client(client):
    index = clients.index(client)
    clients.remove(client)
    alias = aliases[index]
    key = public_keys[index]
    public_keys.remove(key)
    output = f'server_remove:{alias}'
    print("output remove :",output)
    broadcast(output.encode("utf-8"))
    time.sleep(5)
    aliases.remove(alias)
    client.close()

if __name__ == "__main__":
    receive()