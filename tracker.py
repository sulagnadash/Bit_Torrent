import struct
import socket
import random
import string
import urllib.parse
from parser2 import Decoder

# parser reads .torrent file and extracts announce_url and info_hash
# needs "Nametag" before talking with others, provided by generate_peer_id
# take url string from build_tracker_url and uses a socket to send an http get request
# tracker sends back response as bencoded data, parser reads it and turns it into a python dict
# parse_peers helps with reading the bytes from the peers portion of dict, returns clean list of ip and ports
# program loops through them and open TCP connections to start downloading file




# generate 20-byte peer id for client (convention is -<ClientName><Version>-<RandomString>)
def generate_peer_id():

    # Group name 22 + version 1
    prefix = '-220001-'
    allowed_chars = string.ascii_letters + string.digits
    
    randomized = ""
    for i in range(12):
        randomized += random.choice(allowed_chars)
    
    return prefix + randomized

# build URL to send to the tracker
# torrent uses TCP 6881-6889 ports by default
def build_tracker_url(announce_url, info_hash, peer_id, port=6881, file_length=0):
    
    # parameters required by the BitTorrent specification
    params = {'info_hash': info_hash,
            'peer_id': peer_id,
            'port': port,
            'uploaded': 0,
            'downloaded': 0,
            'left': file_length,   # how much is left to download
            'compact': 1,          # tells tracker to send compact binary format (required in pdf)
            'event': 'started'
    }
    
    # encode the parameters into a query string (handles escaping issue with info_hash to avoid misinterpreting URL)
    qs = urllib.parse.urlencode(params)
    
    # combine tracker's address with data parameters using '?' to create the full request URL
    return f"{announce_url}?{qs}"


# parse compact binary response into (ip, port) tuples
# bytes 1-4 are the IP address, bytes 5-6 are port
def parse_peers(binary_peers):
    peers_list = []
    index = 0
    
    # process bytes in chunks of 6 as long as full chunk remains
    while index + 6 <= len(binary_peers):
        
        # extract first 4 bytes as ip address components
        num1 = binary_peers[index]
        num2 = binary_peers[index + 1]
        num3 = binary_peers[index + 2]
        num4 = binary_peers[index + 3]
        
        # merge ip components into string
        ip_string = f"{num1}.{num2}.{num3}.{num4}"
        
        # calculate port from next 2 bytes
        hb = binary_peers[index + 4]
        lb  = binary_peers[index + 5]
        port_number = (hb * 256) + lb
        
        # add to list and move to next chunk
        peers_list.append((ip_string, port_number))
        index += 6
        
    return peers_list

# main function to communicate with tracker
# connects via tcp socket and returns list of peers
def get_peers(torrent_data, info_hash, peer_id):
    
    # get announce url from torrent dictionary
    tracker_url = torrent_data[b'announce']
    if isinstance(tracker_url, bytes):
        tracker_url = tracker_url.decode()
        
    # get total file size for left parameter
    file_len = torrent_data[b'info'].get(b'length', 0)
        
    # build full request url
    full_url = build_tracker_url(tracker_url, info_hash, peer_id, 6881, file_len)
    
    # parse url to get host and port for socket
    parsed = urllib.parse.urlparse(full_url)
    hostname = parsed.hostname
    port = parsed.port or 80
    
    # construct path with query string
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
        
    print(f"Connecting to tracker: {hostname}:{port}")
    
    try:
        # create tcp socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        
        # connect to the tracker
        s.connect((hostname, port))
        
        # send raw http get request
        # must end with double return newline
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        s.sendall(request.encode())
        
        # receive response in chunks
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            
        s.close()
        
        # separate http headers from the body
        # headers end at the first double newline
        header_end = response.find(b"\r\n\r\n")
        if header_end == -1:
            return []
            
        # extract bencoded body
        body = response[header_end + 4:]
        
        # decode the dictionary
        decoded_resp = Decoder(body).decode()
        
        # extract peers key if it exists
        if b'peers' in decoded_resp:
            return parse_peers(decoded_resp[b'peers'])
            
    except Exception as e:
        print(f"Tracker error: {e}")
        
    return []
