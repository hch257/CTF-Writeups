## Quantitative Easing Writeup

### Codegate24 Finals - crypto
>I rolled my own b{lockchain|ank}. Please stimulate our economy!

#### Program  logic
This challenge simulates Bitcoin's UTXO transaction model and uses Bulletproof for off-chain proof generation and on-chain verification. 

Sender should pay tx_fee when transferring value to other users. Sending a transaction requires three steps.

1. The sender requests a transaction, specifying the transaction fee and the transfer value.
2. Receiver response to the transaction, caculating utxo.
3. Finalize the transcation and generate proof. Then send the data, waiting for on-chain verification. Once the verification is successful, propagate the transaction.

The challenge also gives an example.
```python
#### offchain  ####
alice_initial_value = 300
# Spending key for alice
k_a = secrets.randbelow(order)
initial_commitment = commitment(G, H, alice_initial_value, k_a)
chain.genesis_alloc(initial_commitment)
# Alice prepares the transaction
tx_fee, transfer_value = 10, 200
alice = Agent(b"alice", alice_initial_value, k_a)
alice_data = alice.request(tx_fee, transfer_value)
# Spending key for bob
k_b = secrets.randbelow(order)
bob = Agent(b"bob", 0, k_b)
bob_data = bob.response(alice_data)
tx_raw = alice.finalize_tx(bob_data)
###################

####  onchain  ####
assert chain.verify_tx(tx_raw)
chain.propagate_tx()
###################
```

#### Goal : Make the accumulated_tx_fee a very large value.
Initially, bob has a value of 200 and his pk is known to us, which means we can only control a value of 200 in the UTXO set. The required accumulated_tx_fee far exceeds the value that can be manipulated, so the core of the challenge is how to bypass the Bulletproof's range check.
```python
def get_flag(self) -> Dict[str, Any]:
    data = {}
    if (
        self.accumulated_tx_fee
        >= 0x133713371337133713371337133713371337133713371337
    ):
        data["flag"] = open("flag", "rb").read().decode()
    return data
```

#### Bypass range check
Bulletproof is a type of ZKP that enable proving that a secret value falls within a certain range.  When generate a proof for the change-value, `self.value - tx_fee - transfer_value`, it implies that the result falls within the range [0, 2**16 -1]. In this challenge, it uses Secp256k1 as the proof's elliptic curves.

In short, there is a **arithmetic overflow** vulnerability. The tx_fee can be set to a large value exceeding 0x1337..., as long as `tx_fee + transfer_value` exceeds scalar field order, and falls on a reasonable value like `order + 100` in which case the change-value still falls within valid range. 

The vulnerability principle is that the scalar field of secp256k1 is a finite field, where all operations are performed modulo the field order. And the commitment is the linear combination of elliptic curve base points.
```python
def commitment(g, h, x, r):
    return x * g + r * h
```
We can conclude
`self.value - tx_fee - transfer_value = self.value - (tx_fee + transfer_value) mod p`.

#### Attack
The attack process is quite simple.
First, recover Bob and the ProtocolParam through the parameters.
```python
data = json.loads(p.recvline().decode())
PROTOCOL_PARAM = ProtocolParam.from_dict(data)
G, H, U, Gs, Hs, n, m = (
    PROTOCOL_PARAM.G,
    PROTOCOL_PARAM.H,
    PROTOCOL_PARAM.U,
    PROTOCOL_PARAM.Gs,
    PROTOCOL_PARAM.Hs,
    PROTOCOL_PARAM.n,
    PROTOCOL_PARAM.m,
)
data_recv = p.recvline().decode()
data_recv = p.recvline().decode()
print(data_recv)
data = json.loads(data_recv)
print(data)
kb = data["k_b"]
bob = Agent(b"Bob", 200, kb)
# notice that in UTXO set, bob has a value of 200
```

Then, request a transcation and do off-chain proof generation. Bypass the range check through an arithmetic overflow attack.
```python
bob_transfer = bob.request(order - 10, 100)
k_c = secrets.randbelow(order)
coc = Agent(b"coc", 0, k_c) 
coc_data = coc.response(bob_transfer)
tx_raw_2 = bob.finalize_tx(coc_data)
```

Finally, send the transaction data to the server.
```python
tx_raw_2_dump = json.dumps(tx_raw_2)
p.sendline(tx_raw_2_dump)
```

Get the flag
```
codegate2024{Times_29/Aug/2024_Chancellor_on_brink_of_third_bailout_for_banks}
```
