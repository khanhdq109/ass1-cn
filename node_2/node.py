import os
import re
import base64
import requests
import hashlib
import bencodepy
import logging
import flask.cli
import math
import socket
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, send_file, request
from threading import Thread

# Client config
USERNAME = "GUEST"
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_PORT = 8000
# Tracker config
TRACKER_URL = "http://192.168.1.3:5000"
PIECE_SIZE = 524288
FOLDER_NAME = "shared"

app = Flask(__name__)

# Run flask server
def run_flask():
    # Suppress startup banner
    flask.cli.show_server_banner = lambda *args, **kwargs: None

    # Suppress Werkzeug logs
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    app.run(host = CLIENT_IP, port = CLIENT_PORT, debug = False, use_reloader = False)

# Get piece
@app.route('/get_piece', methods = ['GET'])
def get_piece():
    filename = request.args.get("filename")
    index = int(request.args.get("index"))

    name, typ = os.path.splitext(filename)
    piece_filename = f"{name}-piece{index}{typ}"
    piece_path = os.path.join(FOLDER_NAME, piece_filename)

    if not os.path.exists(piece_path):
        return f"[{USERNAME}] Piece not found", 404
    return send_file(piece_path, as_attachment = True)

# Update magnet text
@app.route('/update_magnet', methods = ['POST'])
def update_magnet():
    if 'file' not in request.files:
        return "No file received", 400
    file = request.files['file']
    file.save("magnet.txt")
    return "Received", 200

# Split file into hashed pieces
def split_file(filepath):
    filename = os.path.basename(filepath)
    name_typ = filename.split(".")
    name, typ = name_typ[0], name_typ[1]
    
    pieces = []
    with open(filepath, 'rb') as f:
        i = 0
        while piece := f.read(PIECE_SIZE):
            hash_val = hashlib.sha1(piece).hexdigest()
            pieces.append(hash_val)
            with open(os.path.join(FOLDER_NAME, f"{name}-piece{i}.{typ}"), 'wb') as p:
                p.write(piece)
            i += 1
            
    return pieces

# Download metainfo.torrent from server
def download_metainfo():
    r = requests.get(f"{TRACKER_URL}/metainfo.torrent")
    if r.ok:
        metainfo = bencodepy.decode(r.content)
        return metainfo
    return None

# Extract config from metainfo.torrent
def fetch_metainfo():
    global PIECE_SIZE, FOLDER_NAME
    metainfo = download_metainfo()
    if metainfo:
        PIECE_SIZE = metainfo[b"info"][b"piece_length"]
        FOLDER_NAME = metainfo[b"info"][b"name"].decode()
    else:
        print(f"[{USERNAME}] Failed to fetch metainfo!")
   
# Verify the SHA1 hash of the metainfo matches the one in magnet text     
def verify_magnet_hash(info_dict):
    try:
        with open("magnet.txt", "r") as f:
            magnet_text = f.read().strip()
        
        match = re.search(r"urn:btih:([a-fA-F0-9]+)", magnet_text)
        if not match:
            print(f"[{USERNAME}] Invalid magnet format!")
            return False
    
        expected_hash = match.group(1)
        bencoded_info = bencodepy.encode(info_dict)
        actual_hash = hashlib.sha1(bencoded_info).hexdigest()
        
        if expected_hash == actual_hash:
            return True
        return False
    except FileNotFoundError:
        print(f"[{USERNAME}] magnet.txt not found.")
        return False
    except Exception as e:
        print(f"[{USERNAME}] Error verifying magnet hash: {e}")
        return False
    
def verify_piece(piece_data, expected_hash):
    return hashlib.sha1(piece_data).digest() == expected_hash
        
# Client registers with tracker
def register():
    r = requests.post(f"{TRACKER_URL}/register", json = {"username": USERNAME,"ip": CLIENT_IP, "port": CLIENT_PORT})
    if r.ok:
        print(f"[{USERNAME}] Registered successfully!")
        return True
    else:
        print(f"[GUEST] Username '{USERNAME}' is already used!\n")
        return False

# Client shares a file
def share_file(filepath):
    filename = os.path.basename(filepath)
    pieces = split_file(filepath) # list of sha-1 hash digests
    pieces = b''.join(bytes.fromhex(h) for h in pieces) # join all sha-1 hash digests into one bytes object

    payload = {
        "username": USERNAME,
        "files": {
            "filename": filename,
            "length": os.path.getsize(filepath),
            "pieces": base64.b64encode(pieces).decode(),  # send as base64 string
        }
    }

    r = requests.post(f"{TRACKER_URL}/share", json = payload)
    if r.ok:
        print(f"[{USERNAME}] Shared file '{filename}' successfully!")
    else:
        print(f"[{USERNAME}] Failed to share '{filename}'!")

# Client find a specific file
def find_file(filename):
    r = requests.get(f"{TRACKER_URL}/find", params = {"filename": filename})
    return r.json()

# Client requests a list of all available files    
def list_files():
    r = requests.get(f"{TRACKER_URL}/list")
    return r.json()

# Download multiple files from other clients
def download_file(filenames):
    # Check input
    if not isinstance(filenames, list):
        print(f"[{USERNAME}] Invalid input, expected a list of filenames!")
        return

    # Download metainfo and verify
    metainfo = download_metainfo()
    if not metainfo:
        print(f"[{USERNAME} Failed to download metainfo.torrent]")
        return
    info_dict = metainfo[b"info"]
    if not verify_magnet_hash(info_dict):
        print("HELLO")
        
    all_files = metainfo[b"info"][b"files"]

    def download_single_file(filename):
        # Get peers for this file
        peers = find_file(filename)
        if not peers:
            print(f"[{USERNAME}] No peer has the file '{filename}'!")
            return

        # Determine total pieces
        total_pieces = None
        file_length = None
        for f in all_files:
            file_name = f[b"filename"].decode() if isinstance(f[b"filename"], bytes) else f["filename"]
            if file_name == filename:
                file_length = f[b"length"] if b"length" in f else f["length"]
                total_pieces = math.ceil(file_length / PIECE_SIZE)
                break

        if total_pieces is None:
            print(f"[{USERNAME}] File '{filename}' not found in metainfo!")
            return

        output_path = os.path.join("downloaded", filename)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        downloaded_pieces = [None] * total_pieces

        def download_piece_index(i):
            for ip, port in peers:
                try:
                    url = f"http://{ip}:{port}/get_piece"
                    r = requests.get(url, params={"filename": filename, "index": i}, timeout=5)
                    if r.ok:
                        # Extract expected piece hash from metainfo
                        piece_hashes = f[b"pieces"]
                        expected_hash = piece_hashes[i * 20 : (i + 1) * 20]

                        if verify_piece(r.content, expected_hash):
                            print(f"[{USERNAME}] Downloaded and verified piece {i} of '{filename}' from {ip}:{port}")
                            return i, r.content
                        else:
                            print(f"[{USERNAME}] Hash mismatch for piece {i} from {ip}:{port}")
                except Exception as e:
                    print(f"[{USERNAME}] Error downloading piece {i} of '{filename}' from {ip}:{port}: {e}")
            print(f"[{USERNAME}] Failed to download piece {i} of '{filename}'")
            return i, None

        # Download pieces in parallel
        with ThreadPoolExecutor(max_workers = 8) as executor:
            futures = [executor.submit(download_piece_index, i) for i in range(total_pieces)]
            for future in futures:
                i, content = future.result()
                if content:
                    downloaded_pieces[i] = content
                else:
                    print(f"[{USERNAME}] Could not download piece {i} of '{filename}', aborting...")
                    return

        # Reassemble file
        with open(output_path, "wb") as f:
            for piece in downloaded_pieces:
                f.write(piece)

        print(f"[{USERNAME}] Downloaded '{filename}' completely!")

    # Use threads to download multiple files concurrently
    with ThreadPoolExecutor(max_workers = 4) as executor:
        executor.map(download_single_file, filenames)

# Disconnect, client exit the app
def exit():
    pass
            
def main():
    global USERNAME, CLIENT_IP, CLIENT_PORT, TRACKER_URL, PIECE_SIZE, FOLDER_NAME
    os.makedirs(FOLDER_NAME, exist_ok = True)
    os.makedirs("downloaded", exist_ok = True)
    
    # Get client's information
    print("===========================================================")
    USERNAME = input("Enter your username: ")
    CLIENT_PORT = int(input("Enter your local port: "))
    print("")
    
    # Acts as a server so other clients can download files
    Thread(target = run_flask, daemon = True).start()
        
    # Register new user
    register()
    
    # Fetch metainfo from metainfo.torrent
    fetch_metainfo()

    while True:
        print("\n===========================================================")
        print("\nOptions:")
        print("1. Share file")
        print("2. Find file")
        print("3. List files")
        print("4. Download file")
        print("5. Exit")

        choice = input("Choice: ").strip()
        if choice == "1":
            filepath = input("Enter file path: ").strip()
            print("")
            share_file(filepath)
        elif choice == "2":
            filename = input("Enter file name: ").strip()
            peers = find_file(filename)
            print(peers)
            if peers:
                print(f"\n[{USERNAME}] Find '{filename}':")
                for ip, port in peers:
                    print(f"- Peer: {ip}:{port}")
            else:
                print(f"\n[{USERNAME}] Find '{filename}': No file found!")
        elif choice == "3":
            print(f"\n[{USERNAME}] Request list of files:")
            file_listing = list_files()
            for filename, peers in file_listing.items():
                peer_list = ', '.join([f"{ip}:{port}" for ip, port in peers])
                print(f"- {filename}: {peer_list}")
        elif choice == "4":
            filenames_input = input("Enter filenames to download (separated by commas): ").strip()
            filenames = [name.strip() for name in filenames_input.split(",") if name.strip()]
            if filenames:
                download_file(filenames)
            else:
                print(f"[{USERNAME}] No valid filenames provided!")
        elif choice == "5":
            break
        else:
            print("Invalid choice!")

if __name__ == '__main__':
    main()
