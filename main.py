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
import Crypto
from flask import Flask, jsonify, request, render_template
import requests
from uuid import uuid4
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from threading import Timer
from hashlib import sha512
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto import Hash
from secretstorage import create_collection


this_node = "192.168.143.120:5000"


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
        """check if the chain is valid by comparing the blocks previous hash value to the calculated previous hash"""
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
        return True

    def add_contract(self):
        pass

    def add_node(self, address, new_node):
        """add the address of any nodes to the node set"""
        if address:
            parsed_url = urlparse(address)
            self.node.add(parsed_url.netloc)
        if new_node:
            parse_node = urlparse(new_node)
            self.node.add(parse_node.netloc)
        self.self_node()

    def replace_chain(self):
        """replace this machines chain if a node currently holds a longer valid chain"""
        network = self.node
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f"http://{node}/get_chain")
            if response.status_code == 200:
                length = response.json()["length"]
                chain = response.json()["chain"]
                if length > max_length:
                    if self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

    def self_node(self):
        """make sure this machines address is not in its node set, as will cause infinite loop"""
        list_of_nodes = tuple(self.node)
        node_length = len(list_of_nodes)
        for a in range(node_length):
            if list_of_nodes[a] == this_node:
                list_nodes = set(list_of_nodes)
                list_nodes.remove(this_node)
                self.node = list_nodes
                a += 1

    def propagate_node(self, node):
        """propagate this machines nodes to all machines on the network"""
        self.self_node()
        list_of_nodes = tuple(self.node)
        node_length = len(list_of_nodes)
        if node_length > 1:
            for a in range(node_length):
                deliver_to = "http://" + list_of_nodes[a] + "/receive_propagation"
                requests.post(url=deliver_to, data=node)
                a += 1

    def receive_propagation(self, node):
        """receive the nodes from other machines"""
        self.node.add(node)
        self.self_node()


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


    def get_keys_from_file(self, wallet, passphrase):
        encoded_key = open(f"keys/{wallet}-private.pem", "rb").read()
        key = RSA.import_key(encoded_key,passphrase=passphrase)
        return self.get_wallet(key), key.export_key(), key.publickey().export_key()


    def get_keys_from_wallet(self, wallet, passphrase):
        encoded_key = open(f"keys/{wallet}-private.pem", "rb").read()
        key = RSA.import_key(encoded_key,passphrase=passphrase)
        return key


    def sign_transaction(self, sender_key, reciever_wallet, amount, transaction_ID):
        sender_wallet = self.get_wallet(sender_key)
        string_to_sign = sender_wallet + reciever_wallet + str(amount) + transaction_ID
        signature_object = pkcs1_15.new(sender_key)
        hash = Hash.SHA256.new(string_to_sign.encode("utf8"))
        return signature_object.sign(hash)


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
                        'sender_signature': str(cryptography.sign_transaction(sender_keys, reciever_wallet, amount, transaction_ID).hex()),
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


@app.route("/mine_block", methods=["POST"])
def mine_block():
    '''
    POST command formatted as application/json:
    {
        "wallet", "wallet",
    }
    '''
    json = request.get_json(force=True, silent=True, cache=False)
    wallet = str(json.get("wallet"))
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block["proof"]
    proof = blockchain.proof_of_work(previous_proof, wallet)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    response = {"message": "Congratulations, your block has been mined and added to the Botanical Chain.",
                "index": block["index"],
                "timestamp": block["timestamp"],
                "proof": block["proof"],
                "previous_hash": block["previous_hash"],
                "contracts": block['contracts']}
    return jsonify(response), 200


@app.route("/get_chain", methods=["GET"])
def get_chain():
    """request the current chain"""
    response = {"chain": blockchain.chain,
                "length": len(blockchain.chain)}
    return jsonify(response), 200


@app.route("/is_valid", methods=["GET"])
def is_valid():
    """request if the current chain is valid"""
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {"message": "This nodes Botanical Chain is currently valid"}
    else:
        response = {"message": f"This nodes Botanical Chain is *****INVALID*****"}
    return jsonify(response), 200


@app.route("/connect_node", methods=["POST"])
def connect_node():
    """
    request to connect to a node. Only include addresses of other nodes on the system not yourself.
    POST command formatted as application/json:
    {
        "nodes":   ["http://192.168.1.3:5000/",
                    "http://192.168.1.3:5001/",
                    "http://192.168.1.3:5002/",]
    }
    """
    json = request.get_json(force=True, silent=True, cache=False)
    nodes = json.get("nodes")
    if nodes is None:
        return "No Node", 400
    for nodes in nodes:
        blockchain.add_node(address=nodes, new_node=None)
    response = {"message": "All nodes Connected. The Botanical Chain now contains the nodes:",
                "total_nodes": list(blockchain.node)}
    return jsonify(response), 201


@app.route("/propagate_nodes", methods=["GET"])
def propagate_nodes():
    """sends this machines current nodes to all other machines on the network"""
    list_of_nodes = blockchain.node
    list_of_nodes.add(this_node)
    list_of_nodes = tuple(list_of_nodes)
    node_length = len(list_of_nodes)
    for a in range(node_length):
        blockchain.propagate_node(list_of_nodes[a])
        a += 1
    response = {"message": "Nodes have successfully propagated"}
    return jsonify(response), 201


def propagate_nodes_timer():
    """automatically sends this machines current nodes to all other machines on the network """
    list_of_nodes = blockchain.node
    list_of_nodes.add(this_node)
    list_of_nodes = tuple(list_of_nodes)
    node_length = len(list_of_nodes)
    for a in range(node_length):
        blockchain.propagate_node(list_of_nodes[a])
        a += 1
    print("Nodes have successfully propagated")


print("starting propagation timer, checking every 5 minutes")
rt_one = RepeatedTimer(300, propagate_nodes_timer)


@app.route("/receive_propagation", methods=["POST"])
def receive_propagation():
    """receive data from other machines on the network and update node list"""
    node = request.data.decode('utf-8')
    blockchain.receive_propagation(node)
    response = {"message": "Nodes have successfully propagated"}
    return jsonify(response), 201


@app.route("/join_chain", methods=["POST"])
def join_chain():
    """
    join the chain by sending your current address.
    POST command formatted as application/json:
    {
        "address":   ["http://192.168.1.3:5000/"]
    }
    """
    json = request.get_json(force=True, silent=True, cache=False)
    new_node = str(json.get("address"))
    new_node = new_node.replace("[", "")
    new_node = new_node.replace("]", "")
    new_node = new_node.replace("'", "")
    new_node = new_node.replace("'", "")
    blockchain.add_node(address=None, new_node=new_node)
    blockchain.propagate_node(new_node)
    response = {"message": "You have successfully joined the botanical chain"}
    return jsonify(response), 201


@app.route("/replace_chain", methods=["GET"])
def replace_chain():
    """request to update this machines chain to the longest in the network"""
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {"message": "The node's chain has been replaced with the current longest chain.",
                    "new_chain": blockchain.chain}
    else:
        response = {"message": "The current chain is the longest.",
                    "actual_chain": blockchain.chain}
    return jsonify(response), 200


def replace_chain_timer():
    """request to update this machines chain to the longest in the network - triggered automatically"""
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        print(f"The node's chain has been replaced with the current longest chain.")
    else:
        print(f"The current chain is the longest.")


print("starting consensus timer, checking every 1 minute")
rt_two = RepeatedTimer(60, replace_chain_timer)


@app.route("/see_nodes", methods=["GET"])
def see_nodes():
    """return the nodes in this machines list"""
    nodes = list(blockchain.node)
    response = {"message": nodes}
    return jsonify(response), 200


@app.route("/generate_wallet", methods=["POST"])
def generate_wallet():
    '''
    POST command formatted as application/json:
    {
        "passphrase":   "passphrase"
    }
    '''
    json = request.get_json(force=True, silent=True, cache=False)
    passphrase = str(json.get("passphrase"))
    wallet, private_key, public_key = cryptography.generate_wallet(passphrase)
    response = {"your_wallet_address": wallet,
                "your_public_key": public_key.hex(),
                "your_private_key": private_key.hex(),
                "passphrase": passphrase}
    return jsonify(response), 200


@app.route("/see_mining_wallet", methods=["POST"])
def see_mining_wallet():
    '''
    POST command formatted as application/json:
    {
        "passphrase":   "passphrase"
    }
    '''
    json = request.get_json(force=True, silent=True, cache=False)
    passphrase = str(json.get("passphrase"))
    mining_wallet = blockchain.mining_wallet
    wallet, private_key, public_key = cryptography.get_keys_from_file(mining_wallet, passphrase)
    response = {"your_wallet_address": wallet,
                "your_public_key": public_key.hex(),
                "your_private_key": private_key.hex()
                }
    return jsonify(response), 200


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
    json = request.get_json(force=True, silent=True, cache=False)
    sender_wallet = str(json.get("sender_wallet"))
    passphrase = str(json.get("passphrase"))
    reciever_wallet = str(json.get("reciever_wallet"))
    amount = str(json.get("amount"))
    sender_keys = cryptography.get_keys_from_wallet(sender_wallet, passphrase)
    response = contracts.send_coins(sender_keys, reciever_wallet, amount)
    return jsonify(response), 200


@app.route("/get_balance", methods=["POST"])
def get_balance():
    '''
    POST command formatted as application/json:
    {
        "wallet": "wallet"
    }
    '''
    json = request.get_json(force=True, silent=True, cache=False)
    wallet = str(json.get("wallet"))
    balance = contracts.get_balance(wallet)
    response = {"balance": balance}
    return jsonify(response), 200


app.run (host="0.0.0.0", port=5000)      # change port to run multiple instances on a single machine for development
