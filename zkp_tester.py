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


private_attribute = [1, 2, 3, 4]
(G, o, g1, g2, e) = ((FQ, FQ2, FQ12), curve_order, G1, G2, pairing)

H = [[937845531925087428269928451395687264381131070581694562794817066336771291786, 10091869555272336781048298502942240543342584794990206724695134045518092030170], 
     [16827267555382576560137211493323152595617322234163203392057786728763824890473, 669275743798363724434618058435800127150402866145443086114015005912250752214], 
     [15740660104178268506178465152927295852732903348014859849999260757679338350271, 2740645371567113327431595548550660333966259368680974620804342408116525376959], 
     [18488768737586966185318984113666121536721462619558312891754550708172859077848, 9671219207528200575294542162524725127219225675077023998124257049419968928674], 
     [20054510705574160801992196458479360910375541018232997949962365220188349478315, 12581183077821120942614843399482061950632029325719096752383109041889282325545], 
     [1057184072451964493021664821919836076211130895327550960335797610984967682527, 17335321823455468811849075495436569679150926351307494737525655959821049474861]]

def to_challenge(B_dash, k, H):

    _list = [to_binary256(B_dash)]    
    _list.append(to_binary256(k))

    for i in range(len(H)):
        _list.append(to_binary256(H[i]))

    # _list.append(_Hb)
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def blinding_attribute(private_attribute):
    global H, s_0
    # print(f"H[0]:  {H[0]}")
    t1 = [multiply(H[i+1], (ai)%o) for i, ai in enumerate(private_attribute)]
    s_0 = random.randint(2, o)
    t2 = multiply(H[0], s_0)

    blind_attr = add(t2, ec_sum(t1))

    return blind_attr

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
                                       
def verify_pi_a(B_dash, z, c):
    global H

    print(f"H[0]: {H[0]}, z[0]: {z[0]}")
    print(f"H[1]: {H[1]}, z[1]: {z[1]}")
    print(f"H[2]: {H[2]}, z[2]: {z[2]}")
    k0 =  ec_sum([multiply(H[i], z[i]) for i in range(len(z)) ] )
    
    k1 = multiply(B_dash, (-1 * c)%o)
    k = add(k0, k1)

    c_dash = to_challenge(B_dash , k, H)
    c_dash = c_dash%o

    if(c==c_dash):
        print("Verified")
    else:
        print("Not verified")

for i, h in enumerate(H):
        h = (FQ(h[0]), FQ(h[1]))
        flag = is_on_curve(h, b=3)
        if not flag:
            print("h is not on the curve")
        H[i] = h 

B_dash, z, c = make_pi_a(private_attribute)
verify_pi_a(B_dash, z, c)