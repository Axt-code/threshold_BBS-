import argparse
import jsonpickle
import os
import socket
import subprocess
import time
from py_ecc.bn128 import *
from helper import *


# Constants for retry logic
MAX_RETRIES = 5
RETRY_DELAY = 1  # seconds


def kill_process_using_port(port):
    """
    Kills the process occupying a given port.
    
    :param port: The port to check and free.
    """
    try:
        # Find the PID of the process using the port
        pid = int(subprocess.check_output(["lsof", "-t", "-i:" + str(port)]).strip())
        print(f"Found process {pid} using port {port}. Terminating it.")
        
        # Kill the process
        os.kill(pid, 9)
    except subprocess.CalledProcessError:
        print(f"No process found using port {port}.")
    except Exception as e:
        print(f"Error killing process on port {port}: {e}")


def bind_socket_with_retry(socket_obj, ip, port, retries=MAX_RETRIES, delay=RETRY_DELAY):
    """
    Attempts to bind a socket to a given IP and port with retry logic.
    
    :param socket_obj: The socket object to bind.
    :param ip: The IP address to bind the socket to.
    :param port: The port number to bind the socket to.
    :param retries: Number of attempts to retry in case the port is in use.
    :param delay: Delay between retries in seconds.
    :return: True if successful, False otherwise.
    """
    for attempt in range(retries):
        try:
            socket_obj.bind((ip, int(port)))
            print(f"Successfully bound to IP {ip} on port {port}")
            return True
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print(f"Port {port} is already in use, retrying in {delay} second(s)...")
                kill_process_using_port(port)
                time.sleep(delay)
            else:
                print(f"Failed to bind to port {port}: {e}")
                return False
    return False


def initialize_socket(ip, port):
    """
    Initializes a socket and binds it to a given IP and port.
    
    :param ip: The IP address to bind to.
    :param port: The port to bind to.
    :return: A bound socket object if successful, None otherwise.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if bind_socket_with_retry(s, ip, port):
        s.listen(20)
        return s
    else:
        print(f"Failed to bind socket to IP {ip} on port {port} after multiple attempts.")
        return None


def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Anonymous Credentials Service")
    parser.add_argument("--req-ip", type=str, default='127.0.0.1', help="IP address where the organization is running.")
    parser.add_argument("--req-port", type=str, required=True, help="Port where the organization is running.")
    parser.add_argument("--total-issuers", type=int, required=True, help="Total number of issuers.")
    parser.add_argument("--threshold-issuers", type=int, required=True, help="Threshold number of issuers.")
    args = parser.parse_args()

    # Validate the input for issuers
    if args.threshold_issuers > args.total_issuers:
        print("Threshold issuers cannot be greater than total issuers. Exiting.")
        exit(1)

    # Generate keys for issuers
    print("Generating keys for issuers...")
    sk, vk, X = ttp_keygen(args.threshold_issuers, args.total_issuers)
    
    # # Display generated keys
    # for idx, (secret, public) in enumerate(zip(sk, vk)):
    #     print(f"Issuer {idx} - Secret Key: {secret}, Public Key: {public}\n")
    
    print(f"Common key X: {X}\n")

    # Initialize socket
    socket_obj = initialize_socket(args.req_ip, args.req_port)
    if not socket_obj:
        print("Server initialization failed. Exiting.")
        exit(1)

    print(f"ttp is now listening on {args.req_ip}:{args.req_port}")

    key_request_count = 0
    try:
        while key_request_count < args.total_issuers:
            conn, addr = socket_obj.accept()
            validator = conn.recv(8192).decode()
            print(f"Connection received from: {addr}. Issuer: {validator}")

            try:
                issuer_id = int(validator[1:])  # Assuming issuer ID is the second character onwards
                keys = f"{vk[issuer_id]}:{sk[issuer_id]}:{X}"
                print(f"Issuer {issuer_id} - Secret Key: {sk[issuer_id]}, Public Key: {vk[issuer_id]}, Common key:{X}\n")
                keys_json = jsonpickle.encode(keys)
                conn.send(keys_json.encode())
                key_request_count += 1
            except (ValueError, IndexError):
                print(f"Invalid validator ID: {validator}")
            finally:
                conn.close()

    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        print("Shutting down the server.")
        socket_obj.shutdown(socket.SHUT_RDWR)
        socket_obj.close()


if __name__ == "__main__":
    main()
