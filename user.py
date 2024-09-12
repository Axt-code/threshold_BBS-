from web3 import Web3
import json
import time
from py_ecc.bn128 import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
from helper import *
from hexbytes import HexBytes
import ast

# Connect to local Ethereum node
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))

# Ensure connection is established
if not w3.is_connected():
    raise Exception("Failed to connect to the Ethereum node.")

setup_contract_address = open('SC_output.txt').readlines()[113].strip() if len(open('SC_output.txt').readlines()) >= 114 else "Line 114 does not exist"
user_contract_address = open('SC_output.txt').readlines()[114].strip() if len(open('SC_output.txt').readlines()) >= 115 else "Line 115 does not exist"
issuer_contract_address = open('SC_output.txt').readlines()[115].strip() if len(open('SC_output.txt').readlines()) >= 116 else "Line 116 does not exist"
user_address = "0x359139786D9dC16c9B6f1eb1a378147819F0b234"

# Load the contract ABI
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

# Example data
sid = 1  
sigid = 100 
public_attribute = [100, 200, 300]  # Example public_parameter
private_attribute = [1, 2, 3, 4] 
partial_credential_entries = None
s_0 = None
s_i = None
s = None
U = None
R = None
data_vector = []
H = []
e1=None
X = None
A = None
B = None
(G, o, g1, g2, e) = ((FQ, FQ2, FQ12), curve_order, G1, G2, pairing)
n=4

def broadcast_sig_req(sid, sigid, public_attribute):
    try:
        tx_hash = user_contract.functions.broadcastSigReq(sid, sigid, public_attribute).transact({'from': user_address})
        receipt = w3.eth.waitForTransactionReceipt(tx_hash, timeout=300)
        if receipt.status == 1:
            print("Transaction was successful")
        else:
            print("Transaction failed")
    except Exception as e:
        print(f"An error occurred: {type(e).__name__}, Error details: {e}")

def make_pi_a( private_attribute, H):
    # global s_0
    B_dash = blinding_attribute(private_attribute)
    r = [random.randint(2, o) for i in len(private_attribute)+1]

    k0 = multiply(r[0],s_0)
    k1 = ec_sum([multiply(r[i+1], (ai)%o) for i, ai in enumerate(private_attribute)])
    k = add(k0, k1)

    c = to_challenge(B_dash+k+ [H[i] for i in len(private_attribute)+1])

    z = []
    z.append(add(r[0], multiply(s_0, c)))
    z.append([(r[i+1] + (ai)%o * c)%o] for i, ai in enumerate(private_attribute))

    return (B_dash, z, c)

def blinding_attribute(private_attribute):
    global H, s_0
    t1 = [multiply(H[i+1], (ai)%o) for i, ai in enumerate(private_attribute)]
    
    if(s_0 == None):
        s_0 = random.randint(2, o)
    t2 = multiply(H[0], s_0)

    blind_attr = add(t2, ec_sum(t1))

    return blind_attr


def broadcast_blind_sig_req(sid, sigid, private_attribute ):
    global s_0, H

    blind_attr = blinding_attribute(private_attribute)    
    blind_attr_str = [str(attr) for attr in blind_attr]
    # print(f"blind_attr: {blind_attr_str}")

    pi_a = make_pi_a(private_attribute)

    _B_dash, k, c = pi_a
    # B_dash_str = [str(b) for b in B_dash]

    B_dash = (_B_dash[0].n, _B_dash[1].n)

    try:
        tx_hash = user_contract.functions.broadcastSigReq(sid, sigid, blind_attr_str, B_dash , k, c).transact({'from': user_address})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt.status == 1:
            print("Transaction was successful")
        else:
            print("Transaction failed")
    except Exception as e:
        print(f"An error occurred: {type(e).__name__}, Error details: {e}")

def listen_public_parameter():
    global H, X
    time.sleep(5)  # Adjust sleep duration based on your needs
        # Create a filter to listen for the 'PublicParam' event from the Setup contract
    request_filter = setup_contract.events.PublicParam.create_filter(from_block="latest")
    parameters = request_filter.get_all_entries()
    
    if parameters:
        for event in parameters:
            H = event['args']['H']
            X = event['args']['X']
            # print("Event log entries:", event)
    else:
        print("No events found")
    
    X = X.split("\"")[0]

    X = ast.literal_eval(X) 

    X = decodeToG2(X)
    # print(f"X: {X}\n")

    for i, h in enumerate(H):
        h = (FQ(h[0]), FQ(h[1]))
        flag = is_on_curve(h, b=3)
        if not flag:
            print("h is not on the curve")
        H[i] = h 

def listen_partial_credentials():
    global data_vector, s_i, U, R, e1
    seen_entries = set()  # Set to keep track of unique event entries
    
    # Create the filter outside the loop
    request_filter = issuer_contract.events.PartialCredential.create_filter(from_block="latest")

    while len(data_vector) < n:
        # try:
            # Fetch all entries from the filter
            partial_credential_entries = request_filter.get_all_entries()

            if partial_credential_entries:
                for entry in partial_credential_entries:
                    # Convert the entry to a hashable form to check uniqueness
                    entry_tuple = tuple((k, tuple(v) if isinstance(v, list) else v) for k, v in entry['args'].items())
                    
                    # Only process new unique entries
                    if entry_tuple not in seen_entries:
                        seen_entries.add(entry_tuple)
                        print("\nNew unique event log entry:", entry)

                        sigid = entry['args']['sigid']
                        sid = entry['args']['sid']
                        e1 = entry['args']['e']
                        s = entry['args']['s']
                        s_i = s
                        u_i = entry['args']['u_i']
                        r_i = entry['args']['r']

                        if U is None:
                            U = (u_i)%o
                        else:
                            U = (U + u_i)%o 

                        r_i = (FQ(r_i[0]), FQ(r_i[1]))
                        # print(f"r_i: {r_i}")
                        # flag = is_on_curve(r_i, 3)
                        # if(flag==False):
                        #     print("Not on cure")

                        if R is None:
                            R = r_i
                        else:
                            R = add(R, r_i) 

                        # flag = is_on_curve(R, 3)
                        # if(flag==False):
                        #     print("R is NOT on cure")
                        # else:
                        #     print("R is on cure")

                        # Store the data in the vector
                        data_vector.append({
                            'client': entry['args']['client'],
                            'sid': sid,
                            'sigid': sigid,
                            'e': e1,
                            's': s,
                            'u_i': u_i,
                            'r': r_i,
                        })
                        print("New Entry Added in vector\n")

                        # Check if 3 unique entries have been added, and exit the loop if so
                        if len(data_vector) >= n:
                            print(f"Collected {n} unique entries. Exiting.")
                            return

def make_pi_a( private_attribute):
    global s_0, H
    B_dash = blinding_attribute(private_attribute)
    r = [random.randint(2, o) for _ in range(len(private_attribute)+1)]

    k0 = multiply(H[0], r[0])

    k1 = ec_sum([multiply(H[i+1], r[i+1]) for i in range(len(private_attribute))])
    k = add(k0, k1)

    c = to_challenge(B_dash , k, H)
    c=c%o

    print(f"c: {c}")

    z = []
    z.append((r[0] + (s_0 * c)) % o)

    for i, ai in enumerate(private_attribute):
        z.append((r[i+1] + (ai)%o * c)%o)

    print(f"z: {z}")
    return (B_dash, z, c)

def unblind():
    global s, s_0, s_i
    s = (s_i + s_0)%o
    return s

def verify():
    global U, A, B
    U = U%o
    U_inv = modInverse(U, o)
    print(f"Value of U_inv: {U_inv}")
    A = multiply(R, U_inv)
    print(f"Value of A: {A}")

    t1 = [multiply(H[i+1], (ai)%o) for i, ai in enumerate(private_attribute)]        
    t2 = multiply(H[0], s)
    t = add(t2, ec_sum(t1))

    p21 = add(g1, t)
    B = p21
    # p21 = add(p21, t2)
    flag = is_on_curve(p21, 3)
    if(flag==False):
        print("p21 Not on cure")
    else:
        print("p21 is on curve")

    p2 = pairing(g2, p21)

    print(f"p2: {p2}\n")

    p11 = multiply(g2,e1)

    p12 = add(X, p11)

    p1 = pairing(p12, A)

    print(f"p1: {p1}")
    # print(f"p2: {p2}")

    if(p1==p2):
        print("Verificaltion Successfull...")
    else:
        print("Verificaltion failed...")

def broadcast_show_cred(proof):
    (A_dash,A_bar,d,pi)=proof                                       
    #(c,rm,re,rr2,rr3,rs_dash,_timestamp)=pi
    A_dash = (A_dash[0].n, A_dash[1].n)
    A_bar = (A_bar[0].n, A_bar[1].n)
    d = (d[0].n, d[1].n)
    try:
        tx_hash = user_contract.functions.broadcastSPOK(sid, sigid,pi,A_dash,A_bar,d).transact({'from': user_address})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt.status == 1:
            print("SPOK Transaction was successful")
            print(f"transcation: {tx_hash}")
        else:
            print("SPOK Transaction failed")
    except Exception as e:
        print(f"An error occurred: {type(e).__name__}, Error details: {e}")
    return


listen_public_parameter()

if H is not None and X is not None:
    file_path = 'public_parameters.txt'
    with open(file_path, 'w') as file:
        file.write("H:\n")
        for item in H:
            file.write(f"{item}\n")

        file.write("X:\n")
        file.write(f"{X}\n")

    print(f"Data successfully written to {file_path}")
else:
    print("Failed to retrieve H and X.")

broadcast_blind_sig_req(sid, sigid, private_attribute)

listen_partial_credentials()

print("Got Partial credential\n")

# Print the resulting data map
# print("Final data_vector contents:")
# for entry in data_vector:
#     print(entry)

unblind()


print(f"Value of s: {s}")
print(f"Value of U: {U}")
print(f"Value of R: {R}")

verify()

print("Randomizing credential and giving to serive provider....")
 
params=setup()
sign=(A,e1,s)
proof= make_spok(params, X, private_attribute,public_attribute, B, H,sign)
broadcast_show_cred(proof)
