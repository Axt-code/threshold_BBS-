
import json
from web3 import Web3
from py_ecc.bn128 import *
import time
from helper import *
# from event_listener import listen_public_parameter
import ast


w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs={'timeout': 300}))
if not w3.is_connected():
    raise Exception("Failed to connect to the Ethereum node.")

user_contract_address = open('SC_output.txt').readlines()[114].strip() if len(open('SC_output.txt').readlines()) >= 115 else "Line 115 does not exist"

with open('./build/contracts/User.json') as f:
    tfu = json.load(f)

user_contract = w3.eth.contract(address=user_contract_address, abi=tfu['abi'])


params= setup()
H = []
X = None
proof = None


def read_public_parameters(file_path):
    H = []
    X = None
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()         
            # Read H values
            i = 1
            while i < len(lines) and lines[i].strip() != "X:":
                H.append(eval(lines[i].strip()))  # Convert string representation of list to list
                i += 1

            # Read X value
            if i < len(lines):
                X = lines[i+1].strip()  # Read the X value

        return H, X

    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None, None
    except Exception as e:
        print(f"An error occurred: {type(e).__name__}, Error details: {e}")
        return None, None


def listen_spok():
    request_filter = user_contract.events.SPOKBroadcast.create_filter(from_block="latest")
    parameters = request_filter.get_all_entries()
    
    if parameters:
        print(f"parameters: {parameters}")
        for event in parameters:
            params = event['args']['params']
            points = event['args']['points']
            c = params['c']
            re = params['re']
            rr2 = params['rr2']
            rr3 = params['rr3']
            rs_dash = params['rs_dash']
            _timestamp = params['_timestamp']
            rm = params['rm']
            pi = (c,re,rr2,rr3,rs_dash,_timestamp,rm)
            print("Event log entries:", event)
    else:
        print("No events found")

    print(f"pi:{pi}")
    print(f"type pi:{type(pi)}")
    A_dash = points.A_dash
    A_dash = (FQ(A_dash[0]), FQ(A_dash[1]))
    print(f"A_dash:{A_dash}")
    A_bar = points.A_bar
    A_bar = (FQ(A_bar[0]), FQ(A_bar[1]))
    print(f"A_bar:{A_bar}")
    d = points.d
    d = (FQ(d[0]), FQ(d[1]))
    print(f"d:{d}")
    proof=(A_dash,A_bar,d,pi)
    return proof






file_path = 'public_parameters.txt'

# Retrieve H and X from the file temporary
H, X = read_public_parameters(file_path)

if H is not None and X is not None:
    print("Retrieved H:")
    for item in H:
        print(item)

    print(f"Retrieved X: {X}")
else:
    print("Failed to retrieve data.")
###########################   
#H, X = listen_public_parameter()
X = X.split("\"")[0]
X = ast.literal_eval(X) 
X = decodeToG2(X)
print(f"X: {X}\n")

for i, h in enumerate(H):
    # print("Original h:", h)
    # print(f"type of h[0]: {type(h[0])}")
    # Convert the components of h to FQ elements
    h = (FQ(h[0]), FQ(h[1]))
    
    # Check if the point is on the curve
    flag = is_on_curve(h, b=3)
    if not flag:
        print("h is not on the curve")

    H[i] = h 

public_attribute=[]#change
total_attributes=4 #change


while(proof==None):
    print("waiting for proof...")
    proof=listen_spok()


flag1=verifyCred(params,H, X, proof,public_attribute,total_attributes)

print(f"Credential verification result:{flag1}")

