import socket
import threading
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls 
import time
import random # import randint
from hashlib import sha256 
import os 
from web3.middleware import geth_poa_middleware
from web3 import Web3
import datetime
from ryu.ofproto import ofproto_v1_3
import numpy as np
import secrets
import string
import pyexcel as pe
g = 29
n = 103

'''

provider_url = 'https://sepolia.infura.io/v3/f9e641160e574eba873b5fc1e47a9e69' # "http://10.13.1.65:8545"
w3 = Web3(Web3.HTTPProvider(provider_url))
print (w3.isConnected())

acct_address = '0xEC8e1C11C133fB051AAc28031f27996A5774F70F'
private_key = 'b86092597924b0b4b5fc4c2a1b2e57d9d614b9fce9ca20e75f01a6e27d2e0e00'

auth_abi = '[{"inputs": [{"internalType": "string","name": "HPWi","type": "string"},{"internalType":"string","name": "NVID","type": "string"},{	"internalType": "int256",	"name": "r","type": "int256"	},{"internalType": "int256",	"name": "Cv","type":"int256"},{"internalType": "int256",	"name": "revoc_status","type": "int256"},{"internalType": "int256[]",	"name": "ver_key","type": "int256[]"}],	"name":"store_auth_details","outputs": [],"stateMutability":"nonpayable","type": "function"},{"inputs": [{"internalType":"string","name": "HPW","type": "string"}],	"name":"retrieve_auth_details","outputs": [{"components": [	{"internalType": "string","name": "NVID","type": "string"},	{"internalType": "int256",	"name": "r","type": "int256"	},{"internalType": "int256",	"name": "Cv","type":"int256"},{"internalType": "int256",	"name": "revoc_status","type": "int256"	},{"internalType": "int256[]","name": "ver_key","type": "int256[]"}],"internalType": "struct Auth_SC2.auth_struct",	"name": "","type": "tuple"}],"stateMutability": "view","type": "function"},{"inputs": [{	"internalType":"string","name": "","type": "string"}],"name": "store_veh_auth","outputs": [{"internalType": "string","name": "NVID","type": "string"},{"internalType": "int256","name": "r",	"type": "int256"},{	"internalType": "int256",	"name": "Cv","type": "int256"	},{"internalType": "int256",	"name":"revoc_status","type": "int256"}],"stateMutability": "view","type":"function"}]'
auth_sc_address = "0x3BEC76c13Bd7B6eE56176d893cfEB8e762019590"
'''

provider_url = 'http://127.0.0.1:8545'
w3 = Web3(Web3.HTTPProvider(provider_url))
print (w3.is_connected())

acct_address = '0xE89521136C53455F23e60555fFF7BB6464FD002d'
private_key = "0x90a5a7c3fa8fe82979e58bf87fbcd09381420b716a8dd8f1369dfe1035405afb"
acct = w3.eth.account.from_key('0x90a5a7c3fa8fe82979e58bf87fbcd09381420b716a8dd8f1369dfe1035405afb')

auth_abi = '[{ "inputs": [ { "internalType": "string", "name": "key", "type": "string" } ], "name": "keyExists", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" }, { "inputs":[ { "internalType": "string", "name": "HPW", "type": "string" } ], "name": "retrieve_auth_details", "outputs": [ { "components": [ { "internalType": "string", "name": "NVID", "type": "string" }, { "internalType": "int256", "name":"r", "type": "int256" }, { "internalType": "int256", "name": "Cv", "type": "int256" }, { "internalType": "int256", "name": "revoc_status", "type": "int256" }, { "internalType": "int256[]", "name": "ver_key", "type": "int256[]" } ], "internalType": "struct Auth_SC2.auth_struct", "name": "", "type": "tuple" } ], "stateMutability": "view",  "type":"function" }, { "inputs": [ { "internalType": "string", "name": "HPWi", "type": "string" }, { "internalType":"string", "name": "NVID", "type": "string" }, { "internalType": "int256", "name": "r", "type": "int256" }, { "internalType": "int256", "name": "Cv", "type": "int256" }, { "internalType": "int256", "name":"revoc_status", "type": "int256" }, { "internalType": "int256[]", "name": "ver_key", "type": "int256[]" } ], "name": "store_auth_details", "outputs": [], "stateMutability": "nonpayable", "type": "function" }, { "inputs": [ { "internalType": "string", "name": "", "type": "string" } ], "name": "store_veh_auth", "outputs": [ { "internalType":"string", "name": "NVID", "type": "string" }, { "internalType": "int256", "name": "r", "type":"int256" }, { "internalType": "int256", "name": "Cv", "type": "int256" }, { "internalType": "int256", "name":"revoc_status", "type": "int256" } ], "stateMutability": "view", "type": "function" } ]'
auth_sc_address = "0x6Eab730080CB7a4C810f28DC140758826b9b86Ed"

print ("Acct address is ", acct.address)  

w3_middleware = w3.middleware_onion.inject(geth_poa_middleware, layer=0)
print ("w3_middleware obj is ",w3_middleware)
Chain_id = w3.eth.chain_id 

def listToString(s):
    # initialize an empty string
    str1 = ""
 
    # traverse in the string
    for ele in s:
        str1 += str(ele)
        str1 += ","
    str1 = str1[:len(str1)-1]
    # return string
    return str1

def get_timestamp() :
    ct = datetime.datetime.now()
    ts = ct.timestamp()
    return ts

def xor_sha_strings( s, t): 
    s = bytes.fromhex(s)
    t = bytes.fromhex(t)

    res_bytes = bytes(a^b for a,b in zip(s,t))
    return res_bytes.hex()

def horner(poly, n, x): # poly list(coeff), len(poly), x value to substitute
 
    # Initialize result
    result = poly[0]
 
    # Evaluate value of polynomial
    # using Horner's method
    for i in range(1, n):
 
        result = result*x + poly[i]
 
    return result

class MyController_hand(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController_hand, self).__init__(*args, **kwargs)
        self.sockets = []
        self.lock = threading.Lock()
        

    def start(self):

        host = "10.13.1.220" # socket.gethostname()
        port1 = 8881  # socket server port number
        port2 = 8882
        port3 = 8883
        port4 = 8884
        port5 = 8885
        port6 = 8886
        port7 = 8887
        port8 = 8888
        port9 = 8889
        port10 = 8880
        
        port11 = 8811
        port12 = 8812
        port13 = 8813
        port14 = 8814
        port15 = 8815
        port16 = 8816
        port17 = 8817
        port18 = 8818
        port19 = 8819
        port20 = 8820
        
        port21 = 8821
        port22 = 8822
        port23 = 8823
        port24 = 8824
        port25 = 8825
        port26 = 8826
        port27 = 8827
        port28 = 8828
        port29 = 8829
        port30 = 8830
        port31 = 8831
        

        self.ryu_scket = [None] * 40

        self.ryu_scket[0] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[0].bind((host, port1))  # bind host address and port together
        self.ryu_scket[0].listen(20) 

        self.ryu_scket[1] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[1].bind((host, port2))  # bind host address and port together
        self.ryu_scket[1].listen(20) 

        self.ryu_scket[2] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[2].bind((host, port3))  # bind host address and port together
        self.ryu_scket[2].listen(20) 

        self.ryu_scket[3] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[3].bind((host, port4))  # bind host address and port together
        self.ryu_scket[3].listen(20) 

        self.ryu_scket[4] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[4].bind((host, port5))  # bind host address and port together
        self.ryu_scket[4].listen(20) 

        self.ryu_scket[5] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[5].bind((host, port6))  # bind host address and port together
        self.ryu_scket[5].listen(20) 

        self.ryu_scket[6] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[6].bind((host, port7))  # bind host address and port together
        self.ryu_scket[6].listen(20) 

        self.ryu_scket[7] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[7].bind((host, port8))  # bind host address and port together
        self.ryu_scket[7].listen(20) 

        self.ryu_scket[8] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[8].bind((host, port9))  # bind host address and port together
        self.ryu_scket[8].listen(20) 

        self.ryu_scket[9] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[9].bind((host, port10))  # bind host address and port together
        self.ryu_scket[9].listen(20) 
        
        self.ryu_scket[10] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[10].bind((host, port11))  # bind host address and port together
        self.ryu_scket[10].listen(20)
        
        self.ryu_scket[11] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[11].bind((host, port12))  # bind host address and port together
        self.ryu_scket[11].listen(20)
        
        self.ryu_scket[12] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[12].bind((host, port13))  # bind host address and port together
        self.ryu_scket[12].listen(20)
        
        self.ryu_scket[13] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[13].bind((host, port14))  # bind host address and port together
        self.ryu_scket[13].listen(20)
        
        self.ryu_scket[14] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[14].bind((host, port15))  # bind host address and port together
        self.ryu_scket[14].listen(20)
        
        self.ryu_scket[15] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[15].bind((host, port16))  # bind host address and port together
        self.ryu_scket[15].listen(20)
        
        self.ryu_scket[16] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[16].bind((host, port17))  # bind host address and port together
        self.ryu_scket[16].listen(20)
        
        self.ryu_scket[17] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[17].bind((host, port18))  # bind host address and port together
        self.ryu_scket[17].listen(20)
        
        self.ryu_scket[18] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[18].bind((host, port19))  # bind host address and port together
        self.ryu_scket[18].listen(20)
        
        self.ryu_scket[19] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[19].bind((host, port20))  # bind host address and port together
        self.ryu_scket[19].listen(20)
        
        self.ryu_scket[20] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[20].bind((host, port21))  # bind host address and port together
        self.ryu_scket[20].listen(20)
        
        self.ryu_scket[21] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[21].bind((host, port22))  # bind host address and port together
        self.ryu_scket[21].listen(20)
        
        self.ryu_scket[22] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[22].bind((host, port23))  # bind host address and port together
        self.ryu_scket[22].listen(20)
        
        self.ryu_scket[23] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[23].bind((host, port24))  # bind host address and port together
        self.ryu_scket[23].listen(20)
        
        self.ryu_scket[24] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[24].bind((host, port25))  # bind host address and port together
        self.ryu_scket[24].listen(20)
        
        self.ryu_scket[25] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[25].bind((host, port26))  # bind host address and port together
        self.ryu_scket[25].listen(20)
        
        self.ryu_scket[26] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[26].bind((host, port27))  # bind host address and port together
        self.ryu_scket[26].listen(20)
        
        self.ryu_scket[27] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[27].bind((host, port28))  # bind host address and port together
        self.ryu_scket[27].listen(20)
        
        self.ryu_scket[28] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[28].bind((host, port29))  # bind host address and port together
        self.ryu_scket[28].listen(20)
        
        self.ryu_scket[29] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[29].bind((host, port30))  # bind host address and port together
        self.ryu_scket[29].listen(20)
        
        self.ryu_scket[30] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
        self.ryu_scket[30].bind((host, port31))  # bind host address and port together
        self.ryu_scket[30].listen(20)     
        
        '''
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port1)) 
        self.sock.listen(10)
        '''
        self.logger.info('Waiting for Mininet RSU-Veh to connect...')
        self.logger.info('=============================')
        i = 0
        while True:
            nonce_lock = threading.Lock ()
            global nonce_counter 
            nonce_counter = 0 
            connection, client_address = self.ryu_scket[i].accept()
            self.logger.info('Mininet AP connected: %s:%s', *client_address)
            veh_thread = threading.Thread(target=self.handle_client, args=(connection,))
            i = i + 1
            veh_thread.start()

    def stop(self):
        self.sock.close()
        self.logger.info('Socket closed')

    def send_to_all_mininet_aps(self, data):
        with self.lock:
            for sock in self.sockets:
                sock.sendall(data.encode())
                self.logger.debug('Sent data to Mininet AP: %s', data)

    def handle_client(self, rsu_conn) :

        data = rsu_conn.recv(1024).decode() # HPW, new_NVID, rA_AUth, Tx_ID, T1
        
        hand_start_latency = time.time ()
        
        hand1_start_comp_time = time.time()
        value1 = [str(i) for i in data.split('#')]

        T1 = get_timestamp() 

        if T1 - float(value1[4]) < 4 :

            auth_cont_instance = w3.eth.contract(address = auth_sc_address, abi = auth_abi) # creates an instance of handover contract
     
            check_TID = w3.eth.get_transaction(value1[3])
            # print ("check_TID is ", check_TID)
            tid_BC_hash = check_TID.__dict__["hash"].hex()
    
            if tid_BC_hash ==  value1[3]:
                print ("Transaction happened for Initial Auth for HPW : ", value1[0])
            
                get_HPW_data = auth_cont_instance.functions.retrieve_auth_details(value1[0]).call() # run 

                if get_HPW_data[0] == value1[1] and int(value1[2]) == get_HPW_data[1] : # match new_NVID, rA 
                    ver_key = get_HPW_data[4] # [int(i) for i in get_HPW_data[4].split(',')]

                    rh = random.randint(100, 100000) 

                    msg1 = get_HPW_data[0] +","+ str(rh) +","+ str(get_timestamp())
                    hand1_end_comp_time = time.time ()
                    hand_comp_time = hand1_end_comp_time - hand1_start_comp_time

                    rsu_conn.send(msg1.encode('utf')) # new_NVID, rh
                    data = rsu_conn.recv(1024).decode()

                    hand2_start_comp_time = time.time ()
                    proof_val = [str(i) for i in data.split('&')] # proof pi, rh, T3

                    if get_timestamp() - float(proof_val[2]) < 4 and rh == int(proof_val[1]) :

                        proof = [int(i) for i in proof_val[0].split(',')]

                        alpha = int(ver_key[0])
                        tx_val_on_s = int(ver_key[1])
                        
                        if proof[2] == int(pow(proof[0], alpha, n)): # e(g^p', g) = e(g^p, g^alpha)
                            print (" ----- First proof successful")
                            final_res = int(pow(proof[1], tx_val_on_s, n)) # (g_h * g_t_s_val) % n
                            
                            if proof[0] == final_res:
                                print ("---- Second proof successful")
                                
                                local_veh_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))
                                Sn_key = secrets.token_hex(8)
                                Sn_rand = random.randint(100, 1000)

                                Session_key = local_veh_id +"&"+ Sn_key +"&"+ str(Sn_rand)
                                hand2_end_comp_time = time.time ()

                                hand_comp_time += hand2_end_comp_time - hand2_start_comp_time
                                print ("***** Total comp time at Ryu side is ", hand_comp_time, " sec")
                                rsu_conn.send(Session_key.encode('utf'))
                                print ("Session key sent to RSUs and Vehicle ...")
                                hand_end_latency = time.time ()
                                
                                sheet1 = pe.get_sheet (file_name = "Mani_SDN_hand_latency.xlsx")
                                sheet1.row += [hand_end_latency - hand_start_latency , hand_comp_time]
                                
                                sheet1.save_as ("Mani_SDN_hand_latency.xlsx")

                                print ("***** Total Hand latency is ", hand_end_latency - hand_start_latency, " sec \n *************************\n")
                            else :
                                print ("Second proof invalid")
                        else :
                            print ("First proof invalid")   
                    else :
                        print ("rh does not match or time stamp check failed ....")
                else :
                    print ("new NVID does not match from BC ...")
            else :
                print ("Such a Tx doesn't exist")
        else :
            print ("Time stamp check failed ... Possible session key attack")
      
        print ("------------------------")

        rsu_conn.close()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(ev.msg.data)
        # Process the packet and generate some data to send to the Mininet APs
        data = 'Some data to send to Mininet APs'
        self.send_to_all_mininet_aps(data)

if __name__ == '__main__':
    from ryu import cfg
    from ryu import utils

    cfg.CONF.register_opts([
        cfg.IntOpt('controller1_port', default=6644,
                   help='OpenFlow controller port for App1'),
    ])

    utils.load_modules(['MyController_hand'])
    app_manager.run()
