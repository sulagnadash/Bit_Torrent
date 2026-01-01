import socket
import threading
import struct
import os
import math
from connect_peer import receive_handshake, send_handshake

def read_bytes(sock, num_bytes):
    """
    Helper to read exactly num_bytes from the socket.
    """
    data = b''
    try:
        while len(data) < num_bytes:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
    except:
        return None
    return data

def send_piece(client_socket, index, begin, length, file_path, piece_length):
    """
    Reads a block from disk and sends it to the peer as a PIECE message.
    """
    file_offset = (index * piece_length) + begin
    
    try:
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                f.seek(file_offset)
                block_data = f.read(length)
            
            if block_data:
                # Construct PIECE message: <len=9+X><id=7><index><begin><block>
                msg_len = 9 + len(block_data)
                header = struct.pack(">IBII", msg_len, 7, index, begin)
                client_socket.send(header + block_data)
                print(f"[+] Uploading piece {index} (offset {begin}) to peer")
    except Exception as e:
        # print(f"Error sending piece: {e}")
        pass

def handle_peer_connection(client_socket, torrent_data, peer_id, file_path):
    """
    Worker thread to handle an incoming peer connection (Seeding).
    """
    info_hash = torrent_data[b'info_hash']
    pieces_hash = torrent_data[b'info'][b'pieces']
    total_pieces = len(pieces_hash) // 20
    piece_length = torrent_data[b'info'][b'piece length']
    
    try:
        # 1. Receive Handshake (we don't know the peer_id yet, so pass None)
        res = receive_handshake(client_socket, info_hash, None)
        if not res:
            client_socket.close()
            return

        _, _, remote_peer_id = res
        print(f"[*] Connected to incoming peer {remote_peer_id}")

        # 2. Send Handshake back
        send_handshake(client_socket, info_hash, peer_id)

        # send bitfield message
        bitfield_len = (total_pieces + 7) // 8
        is_seeding = torrent_data.get(b'am_seeding', False)

        if is_seeding:
            bitfield = b'\xff' * bitfield_len
        else:
            bitfield = b'\x00' * bitfield_len

        # Construct and send
        msg = struct.pack(f">IB{bitfield_len}s", 1 + bitfield_len, 5, bitfield)
        client_socket.send(msg)
        print(f"[*] Sent BITFIELD (Seeding) to {remote_peer_id}")

        
        # 3. Enter Message Loop (Wait for requests)
        am_choking = True 
        
        while True:
            # Read length (4 bytes)
            length_data = read_bytes(client_socket, 4)
            if not length_data: break
            
            length = struct.unpack(">I", length_data)[0]
            if length == 0: continue # Keep-alive

            # Read ID (1 byte)
            msg_id_data = read_bytes(client_socket, 1)
            if not msg_id_data: break
            
            msg_id = struct.unpack("B", msg_id_data)[0]

            # Read Payload
            payload = b''
            if length > 1:
                payload = read_bytes(client_socket, length - 1)
                if not payload: break

            # --- Message Handling ---
            
            # INTERESTED (ID=2) -> Send UNCHOKE (ID=1)
            if msg_id == 2: 
                msg = struct.pack(">IB", 1, 1) # Length=1, ID=1 (Unchoke)
                client_socket.send(msg)
                am_choking = False
            
            # REQUEST (ID=6) -> Send PIECE (ID=7)
            elif msg_id == 6: 
                if am_choking: continue 
                
                # Parse: <index><begin><length>
                if len(payload) >= 12:
                    index = struct.unpack(">I", payload[0:4])[0]
                    begin = struct.unpack(">I", payload[4:8])[0]
                    req_len = struct.unpack(">I", payload[8:12])[0]
                    
                    send_piece(client_socket, index, begin, req_len, file_path, piece_length)

    except Exception as e:
        print(f"Peer handler error: {e}")
        pass
    finally:
        client_socket.close()

def server_thread_target(port, torrent_data, peer_id, file_path):
    """
    Main listener loop that accepts connections and spawns threads.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Bind to all interfaces
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"[*] Listener (Server) started on port {port}")
        
        while True:
            try:
                client, addr = server_socket.accept()
                # Start a new thread using the functional style
                t = threading.Thread(
                    target=handle_peer_connection,
                    args=(client, torrent_data, peer_id, file_path)
                )
                t.daemon = True
                t.start()
            except:
                break
                
    except Exception as e:
        print(f"[-] Could not start listener: {e}")

def start_server_thread(port, torrent_data, peer_id, file_path):
    """
    Starts the main server thread.
    """
    t = threading.Thread(
        target=server_thread_target, 
        args=(port, torrent_data, peer_id, file_path)
    )
    t.daemon = True
    t.start()
