import random
import numpy as np
import hashlib
from collections import defaultdict
from typing import List, Tuple
import asyncio
from mpyc.runtime import mpc


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
            print(f"length of own shares and salts {len(self.own_shares_and_salts)}")
            print(f"length of commitments {len(commitments)}")
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
        print(f"expected_commitemnts: {expected_commitments}")
        print(f"self.other_commitments[sender_id].commitments {self.other_commitments[sender_id].commitments}")
        # if expected_commitments != self.other_commitments[sender_id].commitments:
        #     raise ValueError("Incorrect commitment")
        self.other_shares[sender_id] = [share for share, _ in shares_and_salts]

    def compute_joint_randomness(self):
        joint_randomness = []
        for i in range(len(self.own_shares_and_salts)):
            sum = self.own_shares_and_salts[i][0]
            for shares in self.other_shares.values():
                sum += shares[i]
            joint_randomness.append(sum)
        return joint_randomness

    def has_commitment_from(self, id):
        return id in self.other_commitments

    def has_shares_from(self, id):
        return id in self.other_shares

    def has_shares_from_all_who_committed(self):
        return len(self.other_shares) == len(self.other_commitments)

    @staticmethod
    def compute_commitments(shares_and_salts):
        return [hash_function(share, salt) for share, salt in shares_and_salts]

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

async def main():
    
    await mpc.start()
    print(f"mpc.pid: {mpc.pid}")
    issuer_id=mpc.pid
    print(f"issuer_id: {issuer_id}")
    print(f"mpc.parties: {mpc.parties}")
    np_rng = np.random.default_rng()
    

    issuer, commitments = Issuer.commit(np_rng, issuer_id, 1)
    print(f"Commitments: {commitments.commitments}")
    print(f"Issuer_id: {issuer.id}")
    print(f"share: {issuer.own_shares_and_salts}")
    #commitments_share = await mpc.transfer(Commitments, commitments.commitments, senders =issuer_id)
    commitments_share = await mpc.transfer(commitments.commitments)
    print(f"commitments_share: {commitments_share}")
   # shares = await mpc.transfer(commitments_share)
   # print(f"shares: {shares}")
   # print(f"commitment length: {len(commitments_share)}")
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_commitment(party_id, Commitments(commitments_share[party_id]))
            
            #shares_and_salts = [(random.getrandbits(256), np_rng.bytes(32)) for _ in range(1)]
            #issuer.receive_shares(party_id, shares_and_salts)
    shares = await mpc.transfer(issuer.own_shares_and_salts)
    print(f"shares: {shares}")
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_shares(party_id, shares[party_id])

    H0 = issuer.compute_joint_randomness()
    print(f"Issuer {issuer_id} Joint Randomness: {H0}")

    await mpc.shutdown()

    # // generate L values
    L = 10
    H_values = deterministic_random_oracle(H0, L)
    for idx, value in enumerate(H_values):
        print(f"Random value H: {idx+1}: {value}")

if __name__ == '__main__':
    mpc.run(main())