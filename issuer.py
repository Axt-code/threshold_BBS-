import json
from helper import *
from datetime import datetime
import time
from py_ecc.bn128 import *
import argparse
import os
import pickle
import socket
from web3 import Web3
import random
import numpy as np
import hashlib
from collections import defaultdict
from typing import List, Tuple
from mpyc.runtime import mpc
from mpyc.runtime import mpc
# from threshold_bbs import*
import ast

parser = argparse.ArgumentParser(description="Anonymous Credentials registration")
# parser.add_argument("--title", type=str, default=None, required=True, help="This is the title of the Anonymous Credential.")
parser.add_argument("--number-of-attribute", type=int, default=10, required=False, help="Maximum number of attribute issuer can sign.")
parser.add_argument("--req-ip", type=str, default='127.0.0.1', required=False, help="The ip at which organisation is running.")
parser.add_argument("--req-port", type=str, default=None, required=True, help="The port on which organisation is running.")
parser.add_argument("--address", type=str, default=None, required=True, help="The blockchain address on which organization is running.")
parser.add_argument("--rpc-endpoint", type=str, default=None, required=True, help="The node rpc endpoint through which a client is connected to blockchain network.")
parser.add_argument("--Issuer", type=str, default=None, required=True, help="Issuer Id")

args = parser.parse_args()

from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))

# Ensure connection is established
if not w3.is_connected():
    raise Exception("Failed to connect to the Ethereum node.")

# mode = 0o777
setup_contract_address = open('SC_output.txt').readlines()[113].strip() if len(open('SC_output.txt').readlines()) >= 114 else "Line 114 does not exist"
user_contract_address = open('SC_output.txt').readlines()[114].strip() if len(open('SC_output.txt').readlines()) >= 115 else "Line 115 does not exist"
issuer_contract_address = open('SC_output.txt').readlines()[115].strip() if len(open('SC_output.txt').readlines()) >= 116 else "Line 116 does not exist"
issuer_address = args.address

with open('./build/contracts/User.json') as f:
    tfu = json.load(f)

with open('./build/contracts/Issuer.json') as f:
    tfi = json.load(f)

with open('./build/contracts/Setup.json') as f:
    tfs = json.load(f)

# Create contract instance
user_contract = w3.eth.contract(address=user_contract_address, abi=tfu['abi'])
issuer_contract = w3.eth.contract(address=issuer_contract_address, abi=tfi['abi'])
setup_contract = w3.eth.contract(address=setup_contract_address, abi=tfs['abi'])

attributes = []
H0 = None
H_values_G1 = []
sk = None
e=0
s=0
r_i=0
u_i=None
s_id=1
sig_id=100
r_value=None
issuer_id = args.Issuer
issuer_index = int(issuer_id[1:])
X=None
B_dash = []
z = None
c = None
(G, o, g1, g2, e) = setup()

class Commitments:
    def __init__(self, commitments: List[bytes]):
        self.commitments = commitments

class Issuer:
    def __init__(self, id, shares_and_salts: List[Tuple[int, bytes]]):
        self.id = id
        self.own_shares_and_salts = shares_and_salts
        self.other_commitments = {}
        self.other_shares = defaultdict(list)

    @staticmethod
    def commit(rng, id, batch_size):
        shares_and_salts = [(random.getrandbits(256), rng.bytes(32)) for _ in range(batch_size)]
        commitments = Issuer.compute_commitments(shares_and_salts)
        return Issuer(id, shares_and_salts), Commitments(commitments)

    def receive_commitment(self, sender_id, commitments):
        if self.id == sender_id:
            raise ValueError("Sender ID cannot be the same as self ID")
        if sender_id in self.other_commitments:
            raise ValueError("Already have commitment from participant")
        if len(self.own_shares_and_salts) != len(commitments.commitments):
            # print(f"length of own shares and salts {len(self.own_shares_and_salts)}")
            # print(f"length of commitments {len(commitments)}")
            raise ValueError("Incorrect number of commitments")
        self.other_commitments[sender_id] = commitments

    def receive_shares(self, sender_id, shares_and_salts: List[Tuple[int, bytes]]):
        if self.id == sender_id:
            raise ValueError("Sender ID cannot be the same as self ID")
        if sender_id not in self.other_commitments:
            raise ValueError("Missing commitment from participant")
        if sender_id in self.other_shares:
            raise ValueError("Already have shares from participant")
        if len(self.own_shares_and_salts) != len(shares_and_salts):
            raise ValueError("Incorrect number of shares")
        expected_commitments = Issuer.compute_commitments(shares_and_salts)
        self.other_shares[sender_id] = [share for share, _ in shares_and_salts]

    def compute_joint_randomness(self):
        joint_randomness = []
        for i in range(len(self.own_shares_and_salts)):
            sum = self.own_shares_and_salts[i][0]
            for shares in self.other_shares.values():
                sum += shares[i]
            joint_randomness.append(sum)
        return joint_randomness

    @staticmethod
    def compute_commitments(shares_and_salts):
        return [hash_function(share, salt) for share, salt in shares_and_salts]
    
# Open socket connection to port 3000 to get sk and pk pair
def get_pk_sk_pair():
    global sk, X
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.req_ip, 3000))
        s.sendall(args.Issuer.encode('utf-8'))
         # Initialize a list to accumulate the received data
        received_data = []

        while True:
            data = s.recv(1024)  # Receive data in chunks of 1024 bytes
            if not data:
                break  # Break the loop if no more data is received
            # print(f"Received chunk: {data}")
            received_data.append(data)

        # Combine all chunks and decode the full message
        pk_sk_pair = b''.join(received_data).decode('utf-8')
        # print(f"pk_sk_pair and X: {pk_sk_pair}")
        pk, sk, X = pk_sk_pair.split(":")
        # print(f"pk: {pk}")
        # print(f"sk: {sk}")
        # print(f"X: {X}")
        sk = int(sk.split("\"")[0])
        return pk_sk_pair


async def generate_H0():
    await mpc.start()
    global issuer_id
    global H0
    # print(f"mpc.pid: {mpc.pid}")
    issuer_id = mpc.pid
    print(f"issuer_id: {issuer_id}")
    # print(f"mpc.parties: {mpc.parties}")

    np_rng = np.random.default_rng()

    # Initialize issuer
    issuer, commitments = Issuer.commit(np_rng, issuer_id, 1)

    # Share commitments with all parties
    commitments_share = await mpc.transfer(commitments.commitments)


    # Receive commitments from all parties
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_commitment(party_id, Commitments(commitments_share[party_id]))

    # Share own shares with all parties
    shares = await mpc.transfer(issuer.own_shares_and_salts)
    # print(f"shares: {shares}")

    # Receive shares from all parties
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_shares(party_id, shares[party_id])

    # Compute joint randomness
    H0 = issuer.compute_joint_randomness()
    print(f"Issuer {issuer_id} H0_Joint_Random: {H0}")
    
    # print(type(h))
    await mpc.shutdown()

def generate_H():
    global H_values_G1, H0
    L = args.number_of_attribute
    H_values = deterministic_random_oracle(H0[0], L)
    H_values.insert(0, H0[0])


    for value in enumerate(H_values):
        # print(f"New H1: {hashG1(str(value).encode('utf-8'))}")
        H = hashG1(str(value).encode('utf-8'))

        flag = is_on_curve(H, 3)
        if(flag==False):
            print("H Not on cure")

        H_values_G1.append(H)
    

async def mpc_compute_partial_cred():

    global sk, issuer_id, e, s, r_value, u_i
    issuers = len(mpc.parties)
   
    secnum = mpc.SecFld(o)
    e_value = random.randint(2, o)
    secure_e_value = secnum(e_value)

    s_value = random.randint(2, o)
    secure_s_value = secnum(s_value)

    await mpc.start() 
    combined_e,combined_s = await secure_addition(secure_e_value,secure_s_value)
    await mpc.shutdown()

    e=(int(combined_e))%o
    s=(int(combined_s))%o

    print(f"e: {e}")
    print(f"s: {s}")

    # r_value = random.randint(2, o)*(issuer_id+1)

    r_value = (random.randint(2, o)*(issuer_id+1))%o
    print(f"r_value:{r_value}")

    secure_r_value = secnum(r_value)
    indexes=[i+1 for i in range(issuers)]

    lagrange_value = lagrange_basis(indexes,issuer_id+1, o, x=0)
    secret_share = (lagrange_value*sk)%o
    secure_secret_share = secnum(secret_share)
    r_multiply_x =0
    for i in range(issuers):
        if i==mpc.pid:
            mode =1
            await mpc.start() 
            temp = await secure_multiplier(secure_r_value,mode,secure_secret_share,i) 
            await mpc.shutdown()
            # print(f"temp: {temp}")
            r_multiply_x = temp+r_value*secret_share
            # print(f"r_multiply_x:{r_multiply_x}")
        else:
            mode=2
            await mpc.start() 
            temp = await secure_multiplier(secure_r_value,mode,secure_secret_share,i)
            # print(f"temp in mode 2:{temp}")
            await mpc.shutdown()

    u_i = r_multiply_x + r_value*combined_e #denominator of partial credential
    # print(f"u_i:{u_i}")

    u_i = int(u_i)%o

    print(f"e: {e}")
    print(f"s: {s}")
    print(f"u_i: {u_i}")


def listen_broadcast_sig_req():
    global attributes, sig_id, s_id, B_dash, k, c
    # time.sleep(5)
    try:
        request_filter = user_contract.events.SigReqBroadcast.create_filter(from_block="latest")
        entries = request_filter.get_all_entries()
        if entries:
            # print("Event log entries:", entries)
            s_id = entries[0]['args']['sid']
            sig_id = entries[0]['args']['sigid']
            attributes = entries[0]['args']['attribute']
            B_dash = entries[0]['args']['B_dash']
            k = entries[0]['args']['k']
            c = entries[0]['args']['c']
            # print("attributes: ", attributes)
        else:
            return
            print("No events found")
    except Exception as e:
        print(f"An error occurred while listening for events: {e}")

def verify(B_dash, z, c):
    global H_values_G1
    B_dash = (FQ(B_dash[0]), FQ(B_dash[1]))

    k0 =  ec_sum([multiply(H_values_G1[i], z[i]) for i in range(len(z)) ] )
    k1 = multiply(B_dash, (-1 * c)%o)
    k = add(k0, k1)
    c_dash = to_challenge(B_dash , k, H_values_G1)
    c_dash = c_dash%o

    if(c==c_dash):
        print("ZKP Verified...")
    else:
        print("ZKP Not verified...")
        


def listen_attribute_compute_r_i():
    global r_i, r_value, s, H_values_G1, attributes

    # print(f"Length of attributes: {len(attributes)}")
    while(len(attributes)==0):
        listen_broadcast_sig_req()
    
    # print(f"Length of attributes: {len(attributes)}")

    # print("attributes: ", attributes)
    verify(B_dash, k, c)

    attributes_int = [int(x) for x in attributes]
    params = setup()
    r_i = compute_R_i(params, H_values_G1, r_value, s, attributes_int, {} )
    # print(f"r_i: {r_i}")

def issue_partial_credential():
    global r_i, u_i, s_id, sig_id, e, s
    a = (r_i[0].n, r_i[1].n)

    transaction = issuer_contract.functions.issuePartialCredential(
        s_id,
        sig_id,
        e,
        s,
        u_i,
        a
    ).transact({
        'from': issuer_address,
    })
    print(f"transaction : {transaction}")

# Continue with further steps using sk and pk pair
pk_sk_pair = get_pk_sk_pair()
print(f"pk_sk_pair: {pk_sk_pair}")


mpc.run(generate_H0())
generate_H()

for i,values in enumerate(H_values_G1):
    print(f"H{i} : {values}")

# def encodeG2(g2):
# 	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

_H = []
if issuer_index == 0:

    for h in H_values_G1:
        _H.append([h[0].n, h[1].n])  

    _H = tuple(_H)
    transaction = setup_contract.functions.sendPublicParam(
        _H, X
    ).transact({
        'from': issuer_address,
    })

    print(transaction)


mpc.run(mpc_compute_partial_cred())

listen_attribute_compute_r_i()

issue_partial_credential()