
from py_ecc.bn128 import *
#from TTP import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
#import time


def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 3) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def setup(q=1, AC = "h"):
    assert q > 0
    hs = [hashG1((AC+"%s"%i).encode("utf8")) for i in range(q+1)]
    return ((FQ, FQ2, FQ12), curve_order, G1, hs, G2, pairing)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX(x)
        if beta == pow(y, 2, field_modulus):
            return(FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def poly_eval(coeff, x):
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ttp_keygen(params, t, n):
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    assert n >= t and t > 0 and q > 0
    p = [random.randint(2, o) for _ in range(0,t)]
    #x = p[0]%o
    p_i = [poly_eval(p,i) % o for i in range(1,n+1)]
    sk = list(p_i)
    vk = [(g2, multiply(g2, pi)) for pi in p_i]
    vk_serializable = [(str(g2), str(multiply(g2, pi))) for pi in p_i]
    return (sk, vk_serializable)

def ec_sum(list):
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret


def compute_R_i(params,sk,r_i,s,q,BlindAttr=None,message=None):
    (G, o, g1, hs, g2, e) = params
    #message_attribute = 0
    hs_size = len(hs)
    print(f"hs_length:{len(hs)}")
    print(f"message_length:{len(message)}")
    temp_result=None
    if message:
        print(f"message_length:{len(message)}")
        prod_list = [multiply(hs[i+1], mi) for i, mi in enumerate(message)]
        temp_result = ec_sum(prod_list)
    else:
        temp_result=BlindAttr
    #ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments+t1)])
    print(f"type hs[0]:{type(hs[0])}")
    print(f"type s:{type(s)}")
    t1 = (multiply(hs[0], s))
    temp = add(g1,t1) 
    result = add(temp,temp_result)
    #result = ec_sum((multiply(hs[0], s)),t1)
    final_result = multiply(result, r_i)

    return final_result
    
def BlindAttr(message,params):
    (G, o, g1, hs, g2, e) = params
    t1 = [multiply(hs[i+1], mi) for i, mi in enumerate(message)]
    s_0 = random.randint(2, o)
    t2 = (multiply(hs[0], s_0))
    temp_result = ec_sum(t1)
    result = add(t2,temp_result)
    return result          

#to do next generate zero knowledge proofs and verification of proofs

def verify_partial_sign(signature,vk,params):
    return