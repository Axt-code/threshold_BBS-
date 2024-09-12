from py_ecc.bn128 import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
import hashlib
from mpyc.runtime import mpc
# from mpyc.runtime import mpc
import time

def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 3) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX(x)
        if beta == pow(y, 2, field_modulus):
            return(FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def to_binary256(point) :
    if isinstance(point, str):
        return sha256(point.encode("utf8").strip()).digest()
    if isinstance(point, int):
        return point.to_bytes(32, 'big')
    if isinstance(point[0], FQ):
        point1 = point[0].n.to_bytes(32, 'big')
        point2 = point[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()
    if isinstance(point[0], FQ2):
        point1 = point[0].coeffs[0].n.to_bytes(32, 'big') + point[0].coeffs[1].n.to_bytes(32, 'big')
        point2 = point[1].coeffs[0].n.to_bytes(32, 'big') + point[1].coeffs[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0][0], encoded_g2[0][1],]), FQ2([encoded_g2[1][0], encoded_g2[1][1],]))

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

def setup():
    return ((FQ, FQ2, FQ12), curve_order, G1, G2, pairing)

def poly_eval(coeff, x):
    """ evaluate a polynomial defined by the list of coefficient coeff at point x """
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ttp_keygen(t, n ):
    o=curve_order
    g2=G2
    assert n >= t and t > 0
    p = [random.randint(2, o) for _ in range(0,t)]
    # p_i = [poly_eval(p,i) % o for i in range(1,n+1)]
    p_i = [poly_eval(p,i) % o for i in range(0,n+1)]
    sk = list(p_i)
    vk = [(g2, multiply(g2, pi)) for pi in p_i]
    x = p_i[0]
    print(f"x: {x}\n")
    X = multiply(g2, x)
    return (sk[1:], vk[1:], X)

def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret


def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1 
    if (m == 1):
        return 0
    while (a > 1):
        # q is quotient
        q = a // m
        t = m
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
        # Update x and y
        y = x - q * y
        x = t
    # Make x positive
    if (x < 0):
        x = x + m0
    return x

def lagrange_basis(indexes,index, o, x=0):
    """ generates all lagrange basis polynomials """
    l = None
    #for i in indexes:
    numerator, denominator = 1, 1
    for j in indexes:
        if j != index:
            numerator = (numerator * (x - j)) % o
            denominator = (denominator * (index - j)) % o
    l=((numerator * modInverse(denominator, o)) % o)
    return l

def agg_key(params, vks):
    (G, o, g1, hs, g2, e) = params
    
    # filter missing keys (in the threshold setting)
    filter = [vks[i] for i in range(len(vks)) if vks[i] is not None]
    indexes = [i+1 for i in range(len(vks)) if vks[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate keys
    (_, alpha, g1_beta, beta) = zip(*filter)
    q = len(beta[0])
    aggr_alpha = ec_sum([multiply(alpha[i], l[i]) for i in range(len(filter))])
    aggr_g1_beta = [ec_sum([multiply(g1_beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_beta = [ec_sum([multiply(beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_vk = (g2, aggr_alpha, aggr_g1_beta, aggr_beta)
    return aggr_vk

def compute_R_i(params, H_value, r_i, s, BlindAttr=None, message=None):
    (G, o, g1, g2, e) = params

    temp_result=None
    if message:
        # print(f"message_length:{len(message)}")
        prod_list = [multiply(H_value[i+1], mi) for i, mi in enumerate(message)]
        temp_result = ec_sum(prod_list)
    else:
        temp_result = (FQ(BlindAttr[0]), FQ(BlindAttr[1]))
            
        # temp_result=BlindAttr


    flag = is_on_curve(temp_result, 3)
    if(flag==False):
        print("temp_result Not on cure")

    t1 = (multiply(H_value[0], s))
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


#execute below code when credential request is received
async def secure_addition(e_value, s_value):
    # print(f"current issuer id:{mpc.pid}")
    #await mpc.start()
    issuers = len(mpc.parties)
    # print(f"issuers:{issuers}")
    self_id = mpc.pid
    # print(f"self pid:{self_id}")     
    #a_sec = mpc.input(secint(e_value))
    #b_sec = mpc.input(secint(s_value))
    a_sec =  mpc.input(e_value)
    b_sec =  mpc.input(s_value)
    result =  mpc.sum(a_sec) 
    result1 =  mpc.sum(b_sec)  
    res=  await mpc.output(result) 
    res1=  await mpc.output(result1) 
    # print('Addition result of e:', res)
    # print('Addition result of s:', res1)
    #await mpc.shutdown()
    return res, res1

async def secure_multiplier(r_value,mode,secret_share,sender_id):
    # print(f"current issuer id:{mpc.pid}")
    # print(f"Sender id: {sender_id}")
    #print(f" r: {r_value}, other_isuuer: {issuer}")
    #await mpc.start()
    issuers = len(mpc.parties)
    # print(f"issuers:{issuers}")
    self_id = mpc.pid
    print(f"self pid:{self_id}")   
    if mode == 1: #for sender
        sec_num = r_value 
        # print(f"sec_num for mode 1:{sec_num}")
    else:       
        sec_num = secret_share 
        # print(f"sec_num for mode != 1:{sec_num}") 
    a_sec = mpc.input(sec_num)
    #print(f"a_sec:{a_sec[0]}")
    result = 0
    for i in range(issuers):
        if i!=sender_id:
            result = result+mpc.mul(a_sec[sender_id],a_sec[i]) 
            # print(f"result:{result}")
        #else:
            #result = result+0
    res=  await mpc.output(result) 
    # print('Multiplication result:', res)
    #await mpc.shutdown()
    return res

def hash_function(share: int, salt: bytes):
    data = share.to_bytes(32, 'big') + salt
    return hashlib.sha3_256(data).digest()

def deterministic_random_oracle(input_value, L):
    input_str = str(input_value)
    length = len(input_str)
    seed = int(hashlib.sha256(input_str.encode()).hexdigest(), 16)
    random.seed(seed)
    random_values = []
    for _ in range(L):
        random_value = ''.join(random.choices('0123456789', k=length))
        random_values.append(random_value)
    return random_values



#####For signature proving#########
#####statement is 
def to_challenge_spok(elements):
    _list = [to_binary256(x) for x in elements]
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def make_spok(params, vk, private_m,public_m, B, H,sign):
    (G, o, g1, g2, pairing) = params
    (X) = vk
    (A,e,s) = sign
    #####randomize credential
    print(f"A in proof:{A}")
    r1 = random.randint(2, o)
    A_dash= multiply(A, r1)
    print(f"A_dash:{A_dash}")
    r3=modInverse(r1,o)
    print(f"r3:{r3}")
    #r3=(1/r1)%o
    #A_bar = add(modInverse(multiply(A_dash,e),o),multiply(B,r1))
    A_bar = add(neg(multiply(A_dash,e)),multiply(B,r1))
    print(f"A_bar:{A_bar}")
    r2 = random.randint(2, o)
    d = add(multiply(B,r1),neg(multiply(H[0],r2)))
    print(f"d:{d}")
    s_dash = (s-r2*r3)%o
    print(f"s_dash:{s_dash}")
    A_bar_d = add(A_bar,neg(multiply(d,1)))
    ###############
    ###make proof
    wm = [random.randint(2, o) for i in range(len(private_m))]
    we = random.randint(2, o)
    wr2 = random.randint(2, o)
    wr3 = random.randint(2, o)
    ws_dash = random.randint(2, o)
    Aw = add(neg(multiply(A_dash, we)),multiply(H[0],wr2))
    print(f"Aw:{Aw}")
    term_1 = add(multiply(d,wr3),neg(multiply(H[0],ws_dash)))
    Bw = add(term_1, (ec_sum([neg(multiply(H[i+1], wm[i])) for i in range(len(private_m))])))
    print(f"Bw:{Bw}")
    _timestamp = int(time.time())
    c = to_challenge_spok([g1, g2, Aw, Bw, A_bar_d]+ H+public_m+[_timestamp])
    print(f"c:{c}")
    rm = [(wm[i] - c*int(private_m[i])) % o for i in range(len(private_m))]
    re = (we - c*e) % o
    rr2 = (wr2 - c*r2) % o
    rr3 = (wr3 - c*r3) % o
    rs_dash = (ws_dash - c*s_dash) % o
    pi=(c,re,rr2,rr3,rs_dash,_timestamp,rm)
    ############
    term_1 = add(multiply(d,r3),neg(multiply(H[0],s_dash)))
    check2 = add(term_1, (ec_sum([neg(multiply(H[i+1], int(private_m[i]))) for i in range(len(private_m))])))
    print(f"Check2:{check2}")
    

    return(A_dash,A_bar,d,pi)

def verify_spok(params,H, vk, proof,public_m,total_attributes):
    (G, o, g1, g2, pairing) = params
    (X)=vk
    no_of_private_attr = total_attributes-len(public_m)
    print(f"no_of_private_attr:{no_of_private_attr}")
    (A_dash,A_bar,d,pi) = proof
    (c,re,rr2,rr3,rs_dash,_timestamp,rm)=pi
    A_bar_d = add(A_bar,neg(multiply(d,1)))
    Aw = add(multiply(A_bar_d,c),add(neg(multiply(A_dash, re)),multiply(H[0],rr2)))
    term_2 = add(g1,ec_sum([multiply(H[i+1], int(public_m[i])) for i in range(no_of_private_attr, total_attributes)]))
    print(f"check1:{term_2}")   
    Bw = add(multiply(term_2,c),add(add(multiply(d,rr3),neg(multiply(H[0],rs_dash))), (ec_sum([neg(multiply(H[i+1], rm[i]))for i in range(no_of_private_attr)]))))
    #check2= ec_sum([neg(multiply(H[i], rm[i]))for i in range(no_of_private_attr)]) 
    c_bar = to_challenge_spok([g1, g2, Aw, Bw, A_bar_d]+ H+public_m+[_timestamp])
    print(f"Aw:{Aw}")
    print(f"Bw:{Bw}")
    print(f"c_bar:{c_bar}")
    print(f"c:{c}")
    return c_bar==c   


def verifyCred(params,H, vk, proof,public_m,total_attributes):
    (G, o, g1, g2, pairing) = params
    (X)=vk
    (A_dash,A_bar,d,pi) = proof
    assert verify_spok(params,H, X, proof,public_m,total_attributes)
    print(f"g2:{type(g2)}")
    return pairing(X, A_dash)==pairing(g2, A_bar)
#######################

def decodeToG1(i):
    return (FQ(i[0]),FQ(i[1]))

