import struct
import socket
HANDSHAKE_LEN = 68   # handshake should be exactly 68 bytes

# creates connection with a peer using the given ip and port, returns the socket
def connect_to_peer(ip, port):

    #create TCP socket with IPv4 and TCP protocol
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        peer_socket.connect((ip, port))
        return peer_socket
    except socket.error as e:
        print(f"Error connecting to peer {ip}:{port} - {e}")
        return None

# takes a TCP socket, a hash identifying the torrent, and a client id, then the function 
# sends BitTorrent handshake to a peer to start communication
def send_handshake(peer_socket, info_hash, peer_id):
    # protocol string for handshake
    protocol_str = b'BitTorrent protocol'
    pstrlen = len(protocol_str)
    
    # reversed bytes for possible protocol extensions 
    reserved = b'\x00' * 8
    
    # create message, total 68 bytes
    handshake_message = struct.pack(f'B{pstrlen}s8s20s20s', 
                                    pstrlen,            #1 byte
                                    protocol_str,       #19 bytes
                                    reserved,           #8 bytes
                                    info_hash,          #20 bytes
                                    peer_id.encode())   #20 bytes
    

    # send over the socket
    peer_socket.send(handshake_message)

# takes a TCP socket and expected info_hash, receives and validates handshake from peer
# returns a tuple (protocol, info_hash, peer_id)
def receive_handshake(peer_socket, expected_info_hash, expected_peer_id=None):
    # Receive exactly 68 bytes
    data = b''
    while len(data) < HANDSHAKE_LEN:
        chunk = peer_socket.recv(HANDSHAKE_LEN - len(data))
        if not chunk:
            print("Peer closed connection before completing handshake.")
            return None
        data += chunk

    # Parse the handshake
    # 1 byte   - pstrlen
    # 19 bytes - protocol_str
    # 8 bytes  - reserved
    # 20 bytes - info_hash
    # 20 bytes - peer_id

    pstrlen = data[0]
    protocol_str = data[1:1+pstrlen]
    offset = 1 + pstrlen

    reserved = data[offset : offset + 8]
    offset += 8

    info_hash = data[offset : offset + 20]
    offset += 20

    peer_id = data[offset : offset + 20]

    # validate handshake
    if protocol_str != b"BitTorrent protocol":
        print("Invalid protocol string:", protocol_str)
        return None

    if info_hash != expected_info_hash:
        print("Invalid hash:", info_hash)
        return None
    
    if expected_peer_id is not None and peer_id != expected_peer_id:
        print("Invalid peer id:", peer_id)
        return None


    print("Received valid handshake")
    return protocol_str, info_hash, peer_id
