"""
metainfo format:
    {
        "announce": "http://your-tracker-url:port/announce",
        "info": {
            "piece_length": 524288,
            "name": "folder",
            "files": [
                {
                    "filename": "file1.txt", 
                    "length": 12345, 
                    "pieces": <hash_data>
                },
            ]
        }
    }
"""

import os
import json
import base64
import socket
import requests
import bencodepy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

clients = {} # {username: {"addr": (ip, port), "files": []}}
files = {} # {filename: [username1, username2, ...]}

class TrackerHandler(BaseHTTPRequestHandler):
    def _send_response(self, code, content_type = "application/json", body = b""):
        self.send_response(code) 
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*') #
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode()
        data = json.loads(body)

        if self.path == "/register":
            username = data["username"]
            ip = data["ip"]
            port = data["port"]
            clients[username] = {"addr": (ip, port), "files": []}
            
            print(f"[SERVER] User '{username}' registered")
            
            send_magnet_to(username, ip, port)
            
            response = {"message": f"[SERVER] User '{username}' registered!"}
            return self._send_response(200, body = json.dumps(response).encode())

        elif self.path == "/share":
            username = data["username"]
            filename = data["files"]["filename"]
            file_info = data["files"]
            file_info["pieces"] = base64.b64decode(file_info["pieces"])

            if filename not in files:
                files[filename] = []
            if username not in files[filename]:
                clients[username]["files"].append(filename)
                files[filename].append(username)

            update_metainfo(file_info)
            
            print(f"[SERVER] User '{username}' shared a file: '{filename}'!")
            
            response = {"message": f"[SERVER] File '{filename}' shared by '{username}'!"}
            return self._send_response(200, body = json.dumps(response).encode())

        else:
            return self._send_response(404, body = b"Unknown POST endpoint")

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/find":
            filename = query.get("filename", [None])[0]
            if not filename:
                return self._send_response(400, body = b"Missing 'filename' query param")
            peers = find_file(filename)
            return self._send_response(200, body = json.dumps(peers).encode())

        elif parsed.path == "/list":
            file_listing = list_files()
            return self._send_response(200, body = json.dumps(file_listing).encode())

        elif parsed.path == "/metainfo.torrent":
            try:
                with open("metainfo.torrent", "rb") as f:
                    metainfo_data = f.read()
                return self._send_response(200, content_type = 'application/octet-stream', body = metainfo_data)
            except FileNotFoundError:
                return self._send_response(404, body = b"Metainfo not found")

        else:
            return self._send_response(404, body = b"Unknown GET endpoint")

def save_magnet(info_dict):
    # Bencode the metainfo:
    bencoded_info = bencodepy.encode(info_dict)
    
    # SHA1 hash
    info_hash = hashlib.sha1(bencoded_info).hexdigest()
    
    # Create magnet text
    magnet_text = f"magnet:?xt=urn:btih:{info_hash}"
    
    # Save magnet text to .txt file
    with open("magnet.txt", "w") as f:
        f.write(magnet_text)

def send_to_client(username, ip, port, magnet_data):
    url = f"http://{ip}:{port}/update_magnet"
    try:
        r = requests.post(url, files = {"file": ("magnet.txt", magnet_data)}, timeout = 5)
        if r.ok:
            print(f"[SERVER] Sent magnet to {username} ({ip}:{port})")
        else:
            print(f"[SERVER] Failed to send magnet to {username} ({r.status_code})")
    except Exception as e:
        print(f"[SERVER] Error sending magnet to {username} at {ip}:{port}: {e}")

def send_magnet():
    filename = "magnet.txt"
    if not os.path.exists(filename):
        print("[SERVER] No magnet.txt to send!")
        return

    with open(filename, "rb") as f:
        magnet_data = f.read()

    with ThreadPoolExecutor(max_workers = 8) as executor:
        for username, info in clients.items():
            ip, port = info["addr"]
            executor.submit(send_to_client, username, ip, port, magnet_data)
            
def send_magnet_to(username, ip, port):
    filename = "magnet.txt"
    if not os.path.exists(filename):
        print("[SERVER] No magnet.txt to send!")
        return

    with open(filename, "rb") as f:
        magnet_data = f.read()
        
    send_to_client(username, ip, port, magnet_data)
            
def find_file(filename):
    return [clients[user]["addr"] for user in files.get(filename, [])]

def list_files():
    return {fname: [clients[u]["addr"] for u in usrs] for fname, usrs in files.items()}

def create_metainfo(server_ip, server_port, piece_length = 512, folder_name = "shared"):
    # Extract data
    data = {
        "announce": f"http://{server_ip}:{server_port}/announce",
        "info": {
            "piece_length": piece_length * 1024,
            "name": folder_name,
            "files": []
        }
    }
    
    # Save magnet text
    save_magnet(data["info"])
    
    # Save .torrent file
    with open("metainfo.torrent", "wb") as f:
        f.write(bencodepy.encode(data))
    print("[SERVER] Create metainfo.torrent successfully!")

def update_metainfo(file_info):
    # Check valid
    try:
        with open("metainfo.torrent", "rb") as f:
            metainfo = bencodepy.decode(f.read())
    except FileNotFoundError:
        return

    # Update data
    metainfo[b"info"][b"files"].append(file_info)
    
    # Save magnet text
    info = metainfo[b"info"]
    info_dict = {k.decode() if isinstance(k, bytes) else k: v for k, v in info.items()} # Decode bencoded keys to match expected format
    save_magnet(info_dict)
    send_magnet()

    # Save .torrent file
    with open("metainfo.torrent", "wb") as f:
        f.write(bencodepy.encode(metainfo))
    print("[SERVER] Updated metainfo.torrent")

def run_http_server(port = 5000):
    print(f"[SERVER] HTTP Tracker running on port {port}")
    
    # Create metainfo.torrent
    server_ip = socket.gethostbyname(socket.gethostname())
    create_metainfo(server_ip, port)
    
    # Running server
    httpd = HTTPServer(("0.0.0.0", port), TrackerHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[SERVER] Shutting down")
        httpd.server_close()

if __name__ == "__main__":
    run_http_server()