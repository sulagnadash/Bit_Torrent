import sys
import os
import hashlib
import time
from parser2 import Parser         
from tracker import get_peers, generate_peer_id
from files import start_download_with_threads
from server import start_server_thread


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path/to/torrent/file>")
        sys.exit(1)

    torrent_path = sys.argv[1]

    if not os.path.exists(torrent_path):
        print(f"Error: File not found: {torrent_path}")
        sys.exit(1)

    print(f"[*] Loading torrent file: {torrent_path}")

   
    # parse torrent file and compute info_hash
    parser = Parser(torrent_path)
    torrent_data = parser.parse()

    info_hash = parser.get_info_hash()
    print(f"[+] Parsed .torrent file. Info hash = {info_hash.hex()}")

    # determine output filename (single-file torrents)
    if b'info' in torrent_data and b'name' in torrent_data[b'info']:
        out_name = torrent_data[b'info'][b'name'].decode()
    else:
        out_name = "output.dat"

    print(f"[*] Target output file: {out_name}")

    # generate peer_id
    peer_id = generate_peer_id()
    print(f"[+] Generated peer_id = {peer_id}")

    # start listener
    try:
        # Use port from command line if provided, otherwise default to 6881
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 6881
        start_server_thread(port, torrent_data, peer_id, out_name)
    except Exception as e:
        print(f"[-] Warning: Could not start listener: {e}")

    # Contact tracker to get peers
    print("[*] Contacting tracker...")

    try:
        peers = get_peers(torrent_data, info_hash, peer_id)
    except Exception as e:
        print(f"Tracker error: {e}")
        sys.exit(1)

    if not peers:
        print("[-] No peers found from tracker.")
        sys.exit(1)

    print(f"[+] Tracker returned {len(peers)} peers.")

   
    # Start downloading (threads handle connection + handshake)
    print("[*] Starting threaded download...")

    torrent_data[b'info_hash'] = info_hash

    results = start_download_with_threads(
        peers,         
        torrent_data,
        out_name,
        peer_id
    )


    print("[*] Download finished.")
    
    # Check for completeness
    total_pieces = len(torrent_data[b'info'][b'pieces']) // 20
    print(f"[+] Downloaded {len(results)}/{total_pieces} pieces.")

    # calculate and print hash of downloaded file
    if os.path.exists(out_name):
        sha256_hash = hashlib.sha256()
        with open(out_name, 'rb') as f:
            while True:
                chunk = f.read(4096) # Read 4KB at a time
                if not chunk:
                    break
                sha256_hash.update(chunk)
                
        print(f"\n[+] SHA256 hash of downloaded file: {sha256_hash.hexdigest()}")
    else:
        print(f"[-] Downloaded file '{out_name}' not found")

    torrent_data[b'am_seeding'] = True  

    print("[*] Seeding mode active. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
