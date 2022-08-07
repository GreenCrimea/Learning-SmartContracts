'''
BotaniContract
by Tom Horton
1/8/22
******
ALPHA v0.1
******
Updated Botanical blockchain including working cryptography, wallets, transactions, and smartcontracts
'''

import datetime
import hashlib
import json
from urllib import response
from flask import Flask, jsonify, request, render_template, send_file
import requests
from uuid import uuid4
from urllib.parse import urlparse
from threading import Timer
from hashlib import sha512
from Crypto.PublicKey import RSA
from Crypto import Random, Hash
from Crypto.Signature import pkcs1_15
import binascii


this_node = "http://192.168.1.102:5000"


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            print("\n...beep...\n")
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class Blockchain:

    node = set()

    def __init__(self):
        self.chain = []
        self.contracts = []
        self.create_block(proof=1, previous_hash='0')
        self.difficulty_value = 6
        self.node = set()
        self.mining_reward = 1000


    def create_block(self, proof, previous_hash):
        """
        creates a block as a dictionary.
        re-initialises self.transactions back to empty after it is filled by the self.add_transactions method.
        appends the block to the current chain this machine is holding.
        """
        block = {
            "index": len(self.chain) + 1,
            "timestamp": str(datetime.datetime.now()),
            "proof": proof,
            "previous_hash": previous_hash,
            "contracts" : self.contracts
        }
        self.contracts = []
        self.chain.append(block)
        return block

    def hash_difficulty(self):
        """calculate the difficulty value of finding the golden hash"""
        hash_num = ""
        for i in range(self.difficulty_value):
            hash_num += '0'
        return hash_num

    def get_previous_block(self):
        """returns the index number of the previous block in the chain"""
        return self.chain[-1]

    def proof_of_work(self, previous_proof, wallet):
        """find golden hash and return the proof"""
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:self.difficulty_value] == self.hash_difficulty():
                check_proof = True
            else:
                new_proof += 1

        contracts.mining_reward(wallet, self.mining_reward)
        return new_proof

    def hash(self, block):
        """hash entire block and return hashed output"""
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        """check if the chain is valid by comparing the blocks previous hash value to the calculated previous hash, and checking contract signatures"""
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block["previous_hash"] != self.hash(previous_block):
                return False
            previous_proof = previous_block["proof"]
            proof = block["proof"]
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:self.difficulty_value] != self.hash_difficulty():  
                return False
            previous_block = block
            block_index += 1

        for i in range(len(chain)):
            for a in range(len(chain[i]['contracts'])):
                if chain[i]['contracts'][a]['sender_wallet'] != "00000000000000000000000000000000":
                    key = cryptography.get_public_key_from_wallet(chain[i]['contracts'][a]['sender_wallet'])
                    signature_object = pkcs1_15.new(key)  
                    string_to_sign = chain[i]['contracts'][a]['sender_wallet'] + chain[i]['contracts'][a]['reciever_wallet'] + str(chain[i]['contracts'][a]['amount']) + chain[i]['contracts'][a]['transaction_ID']
                    hash = Hash.SHA256.new(string_to_sign.encode("utf8"))
                    try: 
                        signature_object.verify(hash, binascii.unhexlify(chain[i]['contracts'][a]['sender_signature']))
                        continue
                    except ValueError:
                        return False
        return True

    
    def add_node(self, new_node):
        if new_node == this_node:
            pass
        else:
            self.node.add(new_node)

    
    def create_node_dict(self):
        nodes = []
        nodes.append(self.node)
        nodes.append(this_node)
        node_dict = {"nodes": nodes}
        return node_dict


    def propagate_nodes(self):
        node_dict = self.create_node_dict()
        if len(self.node) > 0:
            for i in range(len(self.node)):
                post_to = f"{self.node[i]}recieve_nodes/"
                requests.post(url=post_to, json=node_dict)


    def consensus(self):
        longest_chain = []
        max_length = len(self.chain)
        if len(self.node) > 0:
            for i in range(len(self.node)):
                get_from = f"{self.node[i]}/get_chain_json"
                response = requests.get(url=get_from)
                length = response.json()["length"]
                chain = response.json()["chain"]
                if length > max_length:
                    if self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
            if len(longest_chain) > len(self.chain):
                self.chain = longest_chain


    def push_mempool(self, transaction):
        post_data = {"transaction": transaction}
        for i in range(len(self.node)):
            push_to = f"{self.node[i]}/get_mempool"
            requests.post(url=push_to, json=post_data)

    
    def send_keys(self, wallet):
        private_key = open(f"{wallet}-private.pem", 'r').read()
        public_key = open(f"{wallet}-public.pem", 'r').read()
        message = {"wallet": wallet, "private_key": private_key, "public_key": public_key}
        for i in range(len(self.node)):
            push_to = f"{self.node[i]}/get_keys"
            requests.post(url=push_to, json=message)



class Cryptography:
    
    def __init__(self):
        pass


    def generate_wallet(self, passphrase):
        key = self.generate_RSA_keypair(passphrase)
        return self.get_wallet(key), key.export_key(), key.publickey().export_key()


    def get_wallet_address(self, passphrase):
        wallet, public_key, private_key = self.generate_wallet(passphrase)
        return wallet 
        

    def get_wallet(self, key):
        return hashlib.sha256(key.publickey().export_key()).hexdigest()[:32]


    def generate_RSA_keypair(self, passphrase):
        key = RSA.generate(2048)
        wallet = self.get_wallet(key)
        private_key = key.export_key(passphrase=passphrase)
        file_out = open(f"keys/{wallet}-private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open(f"keys/{wallet}-public.pem", "wb")
        file_out.write(public_key)
        file_out.close()
        return key

    
    def generate_key_file(self, key, passphrase):
        wallet = self.get_wallet(key)
        private_key = key.export_key(passphrase=passphrase)
        file_out = open(f"keys/{wallet}-private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open(f"keys/{wallet}-public.pem", "wb")
        file_out.write(public_key)
        file_out.close()
        return key


    def get_keys_from_file(self, wallet, passphrase):
        encoded_key = open(f"keys/{wallet}-private.pem", "rb").read()
        key = RSA.import_key(encoded_key,passphrase=passphrase)
        return self.get_wallet(key), key.export_key(), key.publickey().export_key()


    def get_keys_from_wallet(self, wallet, passphrase):
        encoded_key = open(f"keys/{wallet}-private.pem", "rb").read()
        key = RSA.import_key(encoded_key,passphrase=passphrase)
        return key


    def get_public_key_from_wallet(self, wallet):
        encoded_key = open(f"keys/{wallet}-public.pem", "rb").read()
        key = RSA.import_key(encoded_key)
        return key


    def sign_transaction(self, sender_key, reciever_wallet, amount, transaction_ID):
        sender_wallet = self.get_wallet(sender_key)
        string_to_sign = sender_wallet + reciever_wallet + str(amount) + transaction_ID
        signature_object = pkcs1_15.new(sender_key)
        hash = Hash.SHA256.new(string_to_sign.encode("utf8"))
        return binascii.hexlify(signature_object.sign(hash)).decode('ascii')


class Contracts:
    
    def __init__(self):
        pass

    def mining_reward(self, wallet, reward):
        transaction_ID = Random.get_random_bytes(32).hex()
        protocol = '00000000000000000000000000000000'
        signature = "MINING_REWARD"
        transaction = {
                        'type': 'TRANSACTION',
                        'transaction_ID': transaction_ID,
                        'reciever_wallet': wallet,
                        'sender_wallet': protocol,
                        'sender_signature': signature,
                        'amount': reward
                        }
        blockchain.contracts.append(transaction)
        return transaction

    def send_coins(self, sender_keys, reciever_wallet, amount):
        transaction_ID = Random.get_random_bytes(32).hex()
        transaction = {
                        'type': 'TRANSACTION',
                        'transaction_ID': transaction_ID,
                        'reciever_wallet': reciever_wallet,
                        'sender_wallet': cryptography.get_wallet(sender_keys),
                        'sender_signature': cryptography.sign_transaction(sender_keys, reciever_wallet, amount, transaction_ID),
                        'amount': int(amount)
                        }
        blockchain.contracts.append(transaction)
        return transaction


    def get_balance(self, wallet):
        balance = 0
        for i in range(len(blockchain.chain)):
            for a in range(len(blockchain.chain[i]['contracts'])):
                if blockchain.chain[i]['contracts'][a]['sender_wallet'] == wallet:
                    balance -= blockchain.chain[i]['contracts'][a]['amount']
                if blockchain.chain[i]['contracts'][a]['reciever_wallet'] == wallet:
                    balance += blockchain.chain[i]['contracts'][a]['amount']
        return balance


app = Flask(__name__, template_folder='template')
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False   # Flask will return an error if this isnt included

node_address = str(uuid4()).replace("-", " ")

contracts = Contracts()
blockchain = Blockchain()
cryptography = Cryptography()


@app.route("/mine_block.html")
def serve_mine_block():
    return render_template('mine_block.html')


@app.route("/mine_block", methods=["POST"])
def mine_block():
    data = request.form
    wallet = data['wallet']
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block["proof"]
    proof = blockchain.proof_of_work(previous_proof, wallet)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    return render_template('block_mined.html', index=block['index'], timestamp=block['timestamp'], proof=block['proof'], previous_hash=block['previous_hash'], contracts=block['contracts'])


@app.route("/get_chain.html")
def get_chain():
    return render_template('get_chain.html', chain=blockchain.chain, length=len(blockchain.chain))


@app.route("/get_chain_json", methods=['GET'])
def get_chain_json():
    response = {"chain": blockchain.chain, "length": len(blockchain.chain)}
    return jsonify(response)


@app.route("/get_mempool", methods=['POST'])
def get_mempool():
    json = request.get_json(force=True, silent=True, cache=False)
    transactions = json.get("transaction")
    for i in range(len(transactions)):
        blockchain.contracts.append(transactions[i])


@app.route("/get_keys", methods=['POST'])
def get_keys():
    json = request.get_json(force=True, silent=True, cache=False)
    wallet = json.get("wallet")
    public_key = json.get("public_key")
    private_key = json.get("private_key")
    file_out = open(f"keys/{wallet}-private.pem", "wb")
    file_out.write(private_key)
    file_out.close()
    file_out = open(f"keys/{wallet}-public.pem", "wb")
    file_out.write(public_key)
    file_out.close()


@app.route("/is_valid.html")
def is_valid():
    """request if the current chain is valid"""
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = 'VALID'
    else:
        response = 'NOT VALID'
    return render_template('is_valid.html', response=response)


print("starting propagation timer, checking every minute")
rt_one = RepeatedTimer(60, blockchain.propagate_nodes)


print("starting consensus timer, checking every 15 seconds")
rt_two = RepeatedTimer(15, blockchain.consensus)


@app.route("/join.html")
def join():
    return render_template('join.html')


@app.route("/join_chain", methods=['POST'])
def join_chain():
    data = request.form
    new_node = str(data['address'])
    blockchain.add_node(new_node)
    blockchain.propagate_nodes()
    return render_template("chain_joined.html")


@app.route("/recieve_nodes", methods=['POST'])
def recieve_nodes():
    json = request.get_json(force=True, silent=True, cache=False)
    nodes = json.get("nodes")
    for i in range(len(nodes)):
        blockchain.add_node(nodes[i])


@app.route("/see_nodes.html")
def see_nodes():
    """return the nodes in this machines list"""
    nodes = list(blockchain.node)
    return render_template('see_nodes.html', nodes=nodes)


@app.route("/generate_wallet.html")
def generate():
    return render_template('generate_wallet.html')


@app.route("/generate_wallet", methods=["POST"])
def generate_wallet():
    data = request.form
    passphrase = str(data["passphrase"])
    wallet, private_key, public_key = cryptography.generate_wallet(passphrase)
    blockchain.send_keys(wallet)
    return render_template('new_wallet.html', wallet=wallet, public=public_key.hex(), private=private_key.hex(), passphrase=passphrase)


@app.route("/send_coins.html")
def coins():
    return render_template('send_coins.html')


@app.route("/send_coins", methods=["POST"])
def send_coins():
    '''
    POST command formatted as application/json:
    {
        "sender_wallet":    "sender_wallet", 
        "passphrase":       "passphrase",
        "reciever_wallet:   "reciever_wallet",
        "amount":           number
    }
    '''
    data = request.form
    sender_wallet = str(data["sender_wallet"])
    passphrase = str(data["passphrase"])
    reciever_wallet = str(data["reciever_wallet"])
    amount = str(data["amount"])
    sender_keys = cryptography.get_keys_from_wallet(sender_wallet, passphrase)
    response = contracts.send_coins(sender_keys, reciever_wallet, amount)
    response["sender_signature"] = str(response["sender_signature"])
    transaction = {
                    'sender_wallet': sender_wallet,
                    'passphrase': passphrase,
                    'reciever_wallet': reciever_wallet,
                    'amount': amount
                    }
    blockchain.push_mempool(transaction)
    return render_template('transaction_successful.html', type=response['type'], ID=response['transaction_ID'], reciever_wallet=response['reciever_wallet'], sender_wallet=response['sender_wallet'], sender_signature=response['sender_signature'], amount=str(response['amount']))


@app.route("/balance.html")
def balance():
    return render_template('balance.html')


@app.route("/get_balance", methods=["POST"])
def get_balance():
    '''
    POST command formatted as application/json:
    {
        "wallet": "wallet"
    }
    '''
    data = request.form
    wallet = str(data["wallet"])
    balance = contracts.get_balance(wallet)
    return render_template('get_balance.html', wallet=wallet, balance=balance)


@app.route("/")
def serve_index():
    return render_template('index.html')


@app.route("/test.html")
def serve_test():
    return render_template('test.html')



app.run (host="0.0.0.0", port=5000, debug=True)      # change port to run multiple instances on a single machine for development
