import hashlib
from typing import Tuple
import json
import sys
from urllib.request import urlopen
from urllib.parse import urlencode
from random import choice
import math
import socket
import threading
from queue import Queue, Empty
import os
import tempfile


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode_helper(bencoded_value, start) -> Tuple[str, int]:
    if chr(bencoded_value[start]).isdigit():
        first_colon_index = start + bencoded_value[start:].find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        str_length = int(bencoded_value[start:first_colon_index])
        value = bencoded_value[
            first_colon_index + 1 : first_colon_index + str_length + 1
        ]
        return value, first_colon_index + str_length + 1
    elif chr(bencoded_value[start]) == "i":
        end = start + bencoded_value[start:].find(ord("e"))
        if end == -1:
            raise ValueError("Non terminated integer")
        value = bencoded_value[start + 1 : end]
        return int(value), end + 1
    elif chr(bencoded_value[start]) == "l":
        next_start = start + 1
        items = []
        while next_start < len(bencoded_value):
            if chr(bencoded_value[next_start]) == "e":
                break
            next_item, next_start = decode_bencode_helper(bencoded_value, next_start)
            items.append(next_item)
        return items, next_start + 1
    elif chr(bencoded_value[start]) == "d":
        value = {}
        next_start = start + 1
        current_key = None
        while next_start < len(bencoded_value):
            if chr(bencoded_value[next_start]) == "e":
                break
            next_item, next_start = decode_bencode_helper(bencoded_value, next_start)
            if current_key is None:
                current_key = next_item.decode("utf-8")
            elif current_key is not None:
                value[current_key] = next_item
                current_key = None
        return value, next_start + 1
    else:
        raise NotImplementedError(f"Unsupported value type {bencoded_value}")


def decode_bencode(bencoded_value):
    result, _ = decode_bencode_helper(bencoded_value, 0)
    return result


def encode_bencode(value) -> bytes:
    match value:
        case int():
            return f"i{value}e".encode()
        case str():
            return f"{len(value)}:{value}".encode()
        case bytes():
            return f"{len(value)}:".encode() + value
        case list():
            result = b"l"
            for item in value:
                result += encode_bencode(item)
            return result + b"e"
        case dict():
            keys = sorted(value.keys())
            result = b"d"
            for key in keys:
                result += encode_bencode(key) + encode_bencode(value[key])
            return result + b"e"
        case _:
            raise ValueError(f"Unsupported value '{value}'")


def parse_torrent(path) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
        return decode_bencode(data)


def get_info_hash(parsed) -> bytes:
    encoded_info = encode_bencode(parsed["info"])
    return hashlib.sha1(encoded_info).digest()


def handshake_message(info_hash) -> bytes:
    message = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
    message += info_hash
    message += b"00112233445566778899"
    return message


def perform_handshake(sock, info_hash) -> bytes:
    message = handshake_message(info_hash)
    sock.sendall(message)
    return sock.recv(len(message))


def bytes_to_int(bs) -> int:
    result = 0
    size = len(bs)
    for i, b in enumerate(bs):
        result ^= b << (8 * (size - i - 1))
    return result


def read_peer_message(sock):
    first_part = b""
    while len(first_part) < 5:
        first_part += sock.recv(5)
    length = bytes_to_int(first_part[:4])
    message_type = first_part[4]
    received = b""
    while len(received) < length - 1:
        received += sock.recv(length - 1)
        print(len(received), "out of", length - 1, "bytes")
    return length, message_type, received


def send_peer_message(sock, mt, payload):
    message = (len(payload) + 1).to_bytes(4)
    message += mt.to_bytes(1)
    message += payload
    sock.sendall(message)


def get_peers(parsed, info_hash):
    url = parsed["announce"].decode("utf-8")
    query = {
        "info_hash": info_hash,
        "peer_id": "00112233445566778899",
        "port": "6881",
        "uploaded": "0",
        "downloaded": "0",
        "left": str(parsed["info"]["length"]),
        "compact": "1",
    }
    url += "?"
    url += urlencode(query)
    peer_list = []
    with urlopen(url) as f:
        result = decode_bencode(f.read())
        peers = result["peers"]
        n_peers = len(peers) // 6
        for i in range(n_peers):
            peer = peers[i * 6 : (i + 1) * 6]
            ip = ".".join(str(b) for b in peer[0:4])
            port = (peer[4] << 8) ^ peer[5]
            peer_list.append((ip, port))
    return peer_list


def request_block(sock, target_piece, n_blocks, i_block, last_block_length):
    # print("******** Getting block", i_block + 1, "out of", n_blocks, "********")
    payload = target_piece.to_bytes(4)
    payload += (i_block * (2**14)).to_bytes(4)
    if i_block == (n_blocks - 1):
        block_size = last_block_length
    else:
        block_size = 2**14
    payload += block_size.to_bytes(4)
    send_peer_message(sock, 6, payload)


def retrieve_block(sock):
    _, mt, result = read_peer_message(sock)
    assert mt == 7, f"Got message type {mt}"
    return result[8:]


def download_piece(parsed, target_piece, output, sock):
    n_pieces = len(parsed["info"]["pieces"]) // 20
    length = parsed["info"]["length"]
    piece_hash = parsed["info"]["pieces"][target_piece * 20 : target_piece * 20 + 20]
    piece_length = parsed["info"]["piece length"]
    last_piece_length = length % piece_length
    last_piece_length = piece_length if last_piece_length == 0 else last_piece_length
    bytes_to_read = last_piece_length if target_piece == n_pieces - 1 else piece_length
    n_blocks = math.ceil(bytes_to_read / (2**14))
    last_block_length = bytes_to_read % (2**14)
    last_block_length = 2**14 if last_block_length == 0 else last_block_length
    _, mt, _ = read_peer_message(sock)
    assert mt == 5
    send_peer_message(sock, 2, b"")
    _, mt, _ = read_peer_message(sock)
    assert mt == 1
    piece_current_hash = hashlib.sha1()
    read_total = 0
    with open(output, "wb+") as f:
        for i_block in range(n_blocks):
            request_block(sock, target_piece, n_blocks, i_block, last_block_length)
            block_data = retrieve_block(sock)
            piece_current_hash.update(block_data)
            f.write(block_data)
            read_total += len(block_data)
        assert piece_current_hash.hexdigest() == piece_hash.hex()


def main():
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        parsed = parse_torrent(sys.argv[2])
        hex_sha = get_info_hash(parsed).hex()
        print("Tracker URL:", parsed["announce"].decode("utf-8"))
        print("Length:", parsed["info"]["length"])
        print("Info Hash:", hex_sha)
        print("Piece Length:", parsed["info"]["piece length"])
        pieces = parsed["info"]["pieces"]
        n_pieces = len(pieces) // 20
        for i in range(n_pieces):
            print(pieces[i * 20 : (i + 1) * 20].hex())
    elif command == "peers":
        parsed = parse_torrent(sys.argv[2])
        info_hash = get_info_hash(parsed)
        peers = get_peers(parsed, info_hash)
        for peer_ip, peer_port in peers:
            print(peer_ip + ":" + str(peer_port))
    elif command == "handshake":
        parsed = parse_torrent(sys.argv[2])
        info_hash = get_info_hash(parsed)
        peer_ip, peer_port = sys.argv[3].split(":")
        port = int(peer_port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_ip, port))
            data = perform_handshake(s, info_hash)
            print("Peer ID:", data[-20:].hex())
    elif command == "download_piece":
        parsed = parse_torrent(sys.argv[4])
        info_hash = get_info_hash(parsed)
        target_piece = int(sys.argv[5])
        output = sys.argv[3]
        peer_ip, peer_port = choice(peers)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_ip, peer_port))
            perform_handshake(s, info_hash)
            download_piece(parsed, target_piece, output, s)
        print(f"Piece {target_piece} downloaded to {output}")
    elif command == "download":
        parsed = parse_torrent(sys.argv[4])
        info_hash = get_info_hash(parsed)
        output = sys.argv[3]
        peers = get_peers(parsed, info_hash)
        queue = Queue()
        print(parsed)
        n_pieces = math.ceil(parsed["info"]["length"] / parsed["info"]["piece length"])
        print(f"Going to get {n_pieces} pieces")
        piece_paths = [None] * n_pieces

        def get_pieces_worker(peer):
            def worker():
                peer_ip, peer_port = peer
                target_piece = None
                while not all(piece_paths):
                    try:
                        target_piece = queue.get(timeout=1)
                        print(f"Got piece number {target_piece} from queue.")
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((peer_ip, peer_port))
                            perform_handshake(s, info_hash)
                            tmp = tempfile.NamedTemporaryFile(delete=False)
                            download_piece(parsed, target_piece, tmp.name, s)
                            piece_paths[target_piece] = tmp.name
                            queue.task_done()
                            target_piece = None
                    except Empty:
                        if all(piece_paths):
                            return
                    except Exception:
                        if target_piece:
                            queue.task_done()
                            queue.put(target_piece)
                    print(f"Done {len([p for p in piece_paths if p])}/{n_pieces}")

            return worker

        threads = [threading.Thread(target=get_pieces_worker(peer)) for peer in peers]
        for thread in threads:
            thread.start()
        for i_piece in range(n_pieces):
            queue.put(i_piece)
        queue.join()
        with open(output, "w+b") as f:
            for piece_path in piece_paths:
                with open(piece_path, "rb") as p:
                    f.write(p.read())
                os.remove(piece_path)
        print(f"Downloaded {sys.argv[4]} to {output}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
