import socket
import threading
import select
import json

SOCKS_VERSION = 5

class Proxy:
    def __init__(self, config_file):
        self.config = self.load_config(config_file)

    def load_config(self, config_file):
        with open(config_file, 'r') as file:
            return json.load(file)

    def handle_client(self, connection):
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)

        if 2 not in set(methods):
            connection.close()
            return

        connection.sendall(bytes([SOCKS_VERSION, 2]))

        username, proxy_settings = self.verify_credentials(connection)
        if not proxy_settings:
            return

        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length).decode()
            address = socket.gethostbyname(address)

        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        try:
            if cmd == 1:  # CONNECT
                remote = self.connect_to_real_proxy(address, port, proxy_settings)
                if remote:
                    bind_address = remote.getsockname()
                    print(f"* Connected to {address} {port} via real proxy {proxy_settings['ip']}")
                else:
                    raise Exception("Failed to connect to real proxy")

                addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
                port = bind_address[1]

                reply = b''.join([
                    SOCKS_VERSION.to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(1).to_bytes(1, 'big'),
                    addr.to_bytes(4, 'big'),
                    port.to_bytes(2, 'big')
                ])
            else:
                connection.close()
                return

        except Exception as e:
            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)

        connection.close()

    def connect_to_real_proxy(self, address, port, proxy_settings):
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((proxy_settings['ip'], proxy_settings['port']))

            remote.sendall(bytes([SOCKS_VERSION, 1, 2]))

            version, method = remote.recv(2)
            if method != 2:
                print("Real proxy does not support USERNAME/PASSWORD authentication")
                return None

            auth_msg = bytes([1, len(proxy_settings['username'])]) + proxy_settings['username'].encode() + \
                       bytes([len(proxy_settings['password'])]) + proxy_settings['password'].encode()
            remote.sendall(auth_msg)

            version, status = remote.recv(2)
            if status != 0:
                print("Authentication failed with real proxy")
                return None

            addr_type = 1 if '.' in address else 3
            connect_msg = bytes([SOCKS_VERSION, 1, 0, addr_type])

            if addr_type == 1:
                connect_msg += socket.inet_aton(address)
            else:
                connect_msg += bytes([len(address)]) + address.encode()

            connect_msg += port.to_bytes(2, 'big')
            remote.sendall(connect_msg)

            response = remote.recv(10)
            if response[1] != 0:
                print("Connection failed with real proxy")
                return None

            return remote
        except Exception as e:
            print(f"Error connecting to real proxy: {e}")
            return None

    def exchange_loop(self, client, remote):
        while True:
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        version = ord(connection.recv(1))

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        for user_config in self.config:
            if username == user_config['username'] and password == user_config['password']:
                response = bytes([version, 0])
                connection.sendall(response)
                return username, user_config['proxy']

        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return None, None

    def get_available_methods(self, nmethods, connection):
        methods = []
        for _ in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()

        print(f"* SOCKS5 proxy server is running on {host}:{port}")

        while True:
            conn, addr = s.accept()
            print(f"* New connection from {addr}")
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()

if __name__ == "__main__":
    config_file = 'config.json'  # Ensure this JSON file is in the same directory
    proxy = Proxy(config_file)
    proxy.run("0.0.0.0", 32325)  # Listen on all interfaces on port 3000
