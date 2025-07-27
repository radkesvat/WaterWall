#!/usr/bin/env python3
"""
TCP Echo Server
Listens on port 443 and echoes back any data received to the sender.
"""

import socket
import threading
import sys
import signal
import time

class TCPEchoServer:
    def __init__(self, host='0.0.0.0', port=443):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        print(f"[INFO] New connection from {client_address[0]}:{client_address[1]}")
        
        try:
            while self.running:
                # Receive data from client
                data = client_socket.recv(4096)
                
                if not data:
                    print(f"[INFO] Client {client_address[0]}:{client_address[1]} disconnected")
                    break
                
                print(f"[DATA] Received from {client_address[0]}:{client_address[1]}: {len(data)} bytes")
                print(f"[DATA] Content: {data[:100]}...")  # Show first 100 bytes
                
                # Echo the data back to the client
                try:
                    client_socket.sendall(data)
                    print(f"[DATA] Echoed {len(data)} bytes back to {client_address[0]}:{client_address[1]}")
                except socket.error as e:
                    print(f"[ERROR] Failed to send data to {client_address[0]}:{client_address[1]}: {e}")
                    break
                    
        except socket.error as e:
            print(f"[ERROR] Socket error with {client_address[0]}:{client_address[1]}: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error with {client_address[0]}:{client_address[1]}: {e}")
        finally:
            client_socket.close()
            print(f"[INFO] Connection closed for {client_address[0]}:{client_address[1]}")
    
    def start(self):
        """Start the TCP echo server"""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow socket reuse
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address and port
            self.server_socket.bind((self.host, self.port))
            
            # Start listening
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[INFO] TCP Echo Server started on {self.host}:{self.port}")
            print(f"[INFO] Listening for connections... (Press Ctrl+C to stop)")
            
            while self.running:
                try:
                    # Accept incoming connections
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"[ERROR] Error accepting connection: {e}")
                    break
                    
        except PermissionError:
            print(f"[ERROR] Permission denied. Port {self.port} requires root privileges.")
            print(f"[INFO] Try running with: sudo python3 {sys.argv[0]}")
            return False
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print(f"[ERROR] Port {self.port} is already in use.")
                print(f"[INFO] Try killing any process using port {self.port} or wait a moment.")
            else:
                print(f"[ERROR] OS error: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to start server: {e}")
            return False
        
        return True
    
    def stop(self):
        """Stop the TCP echo server"""
        print("\n[INFO] Stopping server...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                print(f"[ERROR] Error closing server socket: {e}")
        
        print("[INFO] Server stopped.")

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n[INFO] Received signal {signum}")
    server.stop()
    sys.exit(0)

def main():
    global server
    
    # Parse command line arguments
    host = '0.0.0.0'
    port = 443
    
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"[ERROR] Invalid port number: {sys.argv[1]}")
            sys.exit(1)
    
    if len(sys.argv) > 2:
        host = sys.argv[2]
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start server
    server = TCPEchoServer(host, port)
    
    if not server.start():
        sys.exit(1)
    
    try:
        # Keep the main thread alive
        while server.running:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    main()
