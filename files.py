import struct
import threading
import hashlib
import socket
import time
import json
import queue
from connect_peer import send_handshake, receive_handshake, connect_to_peer
from parser2 import Parser
from tracker import generate_peer_id, get_peers


def save_pieces_to_disk(piece_data, file_path, offset):
    """
    Saves a downloaded piece to disk at the correct offset
    """
    with open(file_path, 'r+b') as file:
        file.seek(offset)
        file.write(piece_data)
    # print(f"Piece saved to {file_path} at offset {offset}.")

def receive_exactly(sock, num_bytes):
    """
    Receive exactly num_bytes from socket.
    """
    data = b""
    sock.settimeout(3.0)
    
    while len(data) < num_bytes:
        try:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        except socket.timeout:
            if len(data) == 0:
                return None
            continue
        except Exception as e:
            print(f"Socket error: {e}")
            return None
    
    return data

# Receive a complete BitTorrent protocol message.
# Returns: (msg_id, payload) tuple or (None, None) for keep-alive
def receive_message(peer_socket):
    try:
        # read 4 bytes for the message
        length_data = receive_exactly(peer_socket, 4)
        # check if none before unpacking
        if not length_data:
            return (None, None)

        length = struct.unpack(">I", length_data)[0]
            
        if length == 0:
            # keep-alive message
            return (None, None)
            
        # read 1 byte for message id
        msg_id_data = receive_exactly(peer_socket, 1)
        if not msg_id_data: 
            return (None, None)

        msg_id = struct.unpack("B", msg_id_data)[0]
            
        # read payload
        payload = b''
        if length > 1:
            payload = receive_exactly(peer_socket, length - 1)
            if not payload:
                return (None, None)

        
        return (msg_id, payload)
            
    except socket.timeout:
        return (None, None)
    except Exception as e:
        print(f"Error receiving message: {e}")
        return (None, None)

# sends interested message to peer (message ID 2)
def send_interested(peer_socket):

    message = struct.pack(">IB", 1, 2)
    peer_socket.send(message)
    #peer_socket.socket.send(message)
    # print(f"Sent interested to {self.ip} {self.port}")

# sends request message to peer for a specific piece/block
def send_request(peer_socket, index, begin, length):
        
    #<len=0013><id=6><index><begin><length>
    message = struct.pack(">IBIII", 13, 6, index, begin, length)

    peer_socket.send(message)
    #peer_socket.socket.send(message)
    # print(f"Requested piece {index}, offset {begin}, length {length}") \

# Send INTERESTED message and wait for UNCHOKE from peer
# Returns: True if unchoked, False if choked or timeout
# Waiting for message 
def wait_for_unchoke(peer_socket):
    send_interested(peer_socket)
    
    start_time = time.time()
    timeout = 10 #wait 10 seconds
    
    while time.time() - start_time < timeout:
        msg_id, payload = receive_message(peer_socket)
        
        if msg_id is None:
            continue
        
        if msg_id == 1:  # UNCHOKE
            # print(f"Peer {peer_socket.getpeername()} unchoked us.")
            return True
        elif msg_id == 0:  # CHOKE
            # print(f"Peer {peer_socket.getpeername()} choked us.")
            return False
    
    # print(f"Timeout waiting for unchoke from {peer_socket.getpeername()}.")
    return False

def handle_initial_messages(peer_socket, total_pieces):
    """
    Handshakes with peer to determine which pieces they have.
    """
    peer_pieces = set()
    is_unchoked = False
    
    try:
        original_timeout = peer_socket.gettimeout()
        peer_socket.settimeout(2.0) 
        
        # Process initial messages
        # Read messages for a short duration to get BITFIELD/HAVE
        start_time = time.time()
        while time.time() - start_time < 3:
            try:
                # Parse message ID
                msg_id, payload = receive_message(peer_socket)
                if msg_id is None:
                    break
                    
                if msg_id == 5:  # BITFIELD message
                    bitfield = bytearray(payload)
                    for i in range(len(bitfield) * 8):
                        if i >= total_pieces: break
                        byte_index = i // 8
                        bit_index = 7 - (i % 8)
                        if (bitfield[byte_index] >> bit_index) & 1:
                            peer_pieces.add(i)

                elif msg_id == 4:  # HAVE message
                    if len(payload) == 4:
                        piece_index = struct.unpack(">I", payload)[0]
                        peer_pieces.add(piece_index)

                elif msg_id == 1:  # UNCHOKE
                    is_unchoked = True
                    return peer_pieces, True

                elif msg_id == 0:  # CHOKE
                    is_unchoked = False
                
            except socket.timeout:
                break
                
        peer_socket.settimeout(original_timeout)
        
    except Exception as e:
        print(f"Error handling initial messages: {e}")

    return peer_pieces, is_unchoked

def download_single_piece(peer_socket, piece_index, piece_length, max_block_size=16384):
    """
    Download pieces using pipeline.
    """
    blocks = []
    for offset in range(0, piece_length, max_block_size):
        length = min(max_block_size, piece_length - offset)
        blocks.append((offset, length))
    
    total_blocks = len(blocks)
    received_count = 0
    data_buffer = bytearray(piece_length)
    
    request_queue = blocks[:]
    pending_offsets = set()
    MAX_PIPELINE = 5
    stall_count = 0 
    
    while received_count < total_blocks:
        # Fill pipeline
        while request_queue and len(pending_offsets) < MAX_PIPELINE:
            offset, length = request_queue.pop(0)
            try:
                send_request(peer_socket, piece_index, offset, length)
                pending_offsets.add(offset)
            except:
                return None

        # Receive response
        try:
            msg_id, payload = receive_message(peer_socket)
        except:
            return None

        if msg_id is None: 
            stall_count += 1
            if stall_count > 5:
                return None
            continue
            
        if msg_id == 0: return None
        
        # Reset stall count on valid message
        stall_count = 0 
        
        # Handle PIECE message
        if msg_id == 7 and payload and len(payload) >= 8:
            resp_index = struct.unpack(">I", payload[0:4])[0]
            resp_offset = struct.unpack(">I", payload[4:8])[0]
            block_data = payload[8:]
            
            if resp_index == piece_index and resp_offset in pending_offsets:
                data_buffer[resp_offset : resp_offset + len(block_data)] = block_data
                pending_offsets.remove(resp_offset)
                received_count += 1
                
    return bytes(data_buffer)

def verify_piece_with_torrent(piece_data, piece_index, torrent_info):
    """
    Verify piece hash against torrent info.
    """
    try:
        # Get piece hashes from torrent info
        pieces_str = torrent_info[b'info'][b'pieces']
        hash_start = piece_index * 20
        hash_end = hash_start + 20
        
        if hash_end > len(pieces_str):
            print(f"Invalid piece index: {piece_index}")
            return False
        
        expected_hash = pieces_str[hash_start:hash_end]
        actual_hash = hashlib.sha1(piece_data).digest()
        
        return actual_hash == expected_hash
        
    except Exception as e:
        print(f"Error verifying piece {piece_index}: {e}")
        return False

def start_download_with_threads(peers, torrent_data, output_file, peer_id):
    """
    Download torrent pieces concurrently from multiple peers using a Queue.
    """
    threads = []
    results = []
    piece_length = torrent_data[b'info'][b'piece length']
    pieces_hash_str = torrent_data[b'info'][b'pieces']
    total_pieces = len(pieces_hash_str) // 20
    
    print(f"Starting download: {total_pieces} pieces, {piece_length} bytes each")
    
    # create a Queue and fill it with every piece index
    work_queue = queue.Queue()
    for i in range(total_pieces):
        work_queue.put(i)
    
    # Create output file with correct size
    total_size = torrent_data[b'info'][b'length']
    with open(output_file, 'wb') as f:
        f.write(b'\x00' * total_size)
    
    # Distribute pieces among available peers
    if not peers:
        print("No peers available for download")
        return []
    
    print(f"Spawning threads for {len(peers)} peers...")
    
    for i, peer_info in enumerate(peers):
        ip, port = peer_info
        
        # Start download thread with shared queue
        thread = threading.Thread(
            target=download_worker,
            args=(ip, port, work_queue, piece_length, output_file, torrent_data, results, peer_id, total_pieces)
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print(f"Download complete. Downloaded {len(results)} pieces")
    return results

def download_worker(ip, port, work_queue, piece_length, file_path, torrent_data, results, peer_id, total_pieces):
    """
    Worker thread function for downloading pieces from queue
    """
    peer_socket = None

    file_length = torrent_data[b'info'][b'length']

    try:
        # Connect to peer 
        peer_socket = connect_to_peer(ip, port)
        if not peer_socket: return
            
        # Perform handshake 
        send_handshake(peer_socket, torrent_data[b'info_hash'], peer_id)
        if not receive_handshake(peer_socket, torrent_data[b'info_hash']):
            peer_socket.close()
            return
        
        # Get Bitfield
        peer_pieces, unchoked = handle_initial_messages(peer_socket, total_pieces)

        # Wait for Unchoke
        if not unchoked:
            if not wait_for_unchoke(peer_socket):
                peer_socket.close()
                return

        # Loop until queue is empty
        skips = 0
        while not work_queue.empty():
            try:
                # Grab a job
                piece_index = work_queue.get_nowait()
            except queue.Empty:
                break

            # Check if peer actually has this piece
            if piece_index not in peer_pieces:
                work_queue.put(piece_index)
                skips += 1
                time.sleep(0.5)
                if skips > 10:
                    break
                continue
            
            skips = 0

            print(f"Downloading piece {piece_index} from {ip}")
            
            if piece_index == total_pieces - 1:
                remainder = file_length % piece_length
                current_piece_size = remainder if remainder > 0 else piece_length
            else:
                current_piece_size = piece_length

            try:
                piece_data = download_single_piece(peer_socket, piece_index, current_piece_size)
                
                # Verify and Save
                if piece_data and verify_piece_with_torrent(piece_data, piece_index, torrent_data):
                    offset = piece_index * piece_length
                    save_pieces_to_disk(piece_data, file_path, offset)
                    results.append((piece_index, True))
                    print(f"Piece {piece_index} verified and saved")
                else:
                    print(f"Failure handling piece {piece_index} from {ip}. Dropping connection.")
                    work_queue.put(piece_index)
                    break

            
            except Exception as e:
                print(f"Connection error with {ip}: {e}")
                work_queue.put(piece_index)
                break

    except Exception as e:
        # print(f"Download worker error: {e}")
        pass
    finally:
        if peer_socket:
            peer_socket.close()

def download_torrent(torrent_file, output_file):
    """
    Complete torrent download
    """
    # Parse torrent file
    parser = Parser(torrent_file)
    torrent_data = parser.parse()
    
    torrent_data[b'info_hash'] = parser.get_info_hash()
    peer_id = generate_peer_id()
    file_length = torrent_data[b'info'][b'length']

    # Get peers from tracker
    peers = get_peers(torrent_data, parser.get_info_hash(), peer_id)
    if not peers:
        print("No peers found")
        return
    
    print(f"Found {len(peers)} peers")
    
    # Start downloading
    results = start_download_with_threads(peers, torrent_data, output_file, peer_id)
    
    # Verify all pieces were downloded
    total_pieces = len(torrent_data[b'info'][b'pieces']) // 20
    downloaded_count = len(set(piece_index for piece_index, _ in results))
    
    if downloaded_count == total_pieces:
        print("All pieces downloaded successfully!")
    else:
        print(f"Downloaded {downloaded_count}/{total_pieces} pieces")
