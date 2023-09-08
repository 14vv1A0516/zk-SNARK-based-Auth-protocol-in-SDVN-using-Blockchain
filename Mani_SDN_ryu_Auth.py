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
#os.system ("pip install pyexcel")
from web3 import Web3
import numpy as np
import datetime
from ryu.ofproto import ofproto_v1_3
 
import pyexcel as pe
from web3.middleware import geth_poa_middleware
g = 29
n = 103

provider_url = 'http://127.0.0.1:8545'
w3 = Web3(Web3.HTTPProvider(provider_url))
print (w3.is_connected())

reg_abi = '[{"inputs": [{"internalType": "string",	"name": "HPW","type": "string"}],"name": "retrieve_reg_details","outputs": [{"components": [{"internalType": "string","name": "NVID","type": "string"},{"internalType": "int256[]","name":"teq_coff",	"type": "int256[]"},{"internalType": "int256","name": "degree","type": "int256"	},{"internalType": "int256","name": "Cv",	"type": "int256"},{"internalType": "int256","name": "revoc_status","type":"int256"}],"internalType": "struct Reg_SC1.reg_struct","name": "","type": "tuple"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "string","name": "HPWi","type":"string"},{"internalType": "string","name": "NVID","type": "string"},{"internalType": "int256[]","name":"teq_coff",	"type": "int256[]"},{"internalType": "int256","name": "degree","type": "int256"	},{"internalType": "int256","name": "Cv",	"type": "int256"},{"internalType": "int256","name": "revoc_status","type":"int256"}],"name": "store_reg_details","outputs": [],"stateMutability": "nonpayable","type":"function"},{"inputs": [{"internalType": "string","name": "","type": "string"}],"name":"store_veh_reg","outputs": [{"internalType": "string","name": "NVID","type": "string"},{"internalType":"int256","name": "degree","type": "int256"},{"internalType": "int256","name": "Cv",	"type": "int256"},{"internalType": "int256","name": "revoc_status","type": "int256"}],"stateMutability": "view","type": "function"}]'

acct_address = '0xE89521136C53455F23e60555fFF7BB6464FD002d'

reg_sc_address = '0xE909E9F05D332359F4D6Fc841d7Ea0B1056E3e02'
private_key = '0x90a5a7c3fa8fe82979e58bf87fbcd09381420b716a8dd8f1369dfe1035405afb'
acct = w3.eth.account.from_key('0x90a5a7c3fa8fe82979e58bf87fbcd09381420b716a8dd8f1369dfe1035405afb')

auth_abi = '[{"inputs": [{"internalType": "string",	"name": "HPWi","type": "string"},{"internalType":"string","name": "NVID","type": "string"},{"internalType": "int256",	"name": "r","type": "int256"},{"internalType": "int256","name": "Cv","type":"int256"},{"internalType": "int256", "name": "revoc_status","type":"int256"},{"internalType": "int256[]","name": "ver_key","type":"int256[]"}],"name": "store_auth_details","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType":"string","name": "HPW","type": "string"}],"name":"retrieve_auth_details","outputs": [{"components": [{"internalType":"string","name": "NVID","type": "string"},{"internalType": "int256",	"name": "r","type": "int256"},{"internalType": "int256","name": "Cv","type":"int256"},{"internalType": "int256","name": "revoc_status","type": "int256"},{"internalType": "int256[]","name": "ver_key","type": "int256[]"}],	"internalType":"struct Auth_SC2.auth_struct","name": "","type":"tuple"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "string","name": "","type": "string"}],"name": "store_veh_auth","outputs": [{"internalType": "string","name": "NVID","type": "string"},{"internalType": "int256","name": "r","type": "int256"},{"internalType": "int256",	"name": "Cv","type": "int256"},{"internalType": "int256","name": "revoc_status","type": "int256"}],"stateMutability": "view","type": "function"}]'

auth_sc_address = "0x08757B1F3B88AaB4B30C68B731b6069A557AB991"
w3_middleware = w3.middleware_onion.inject(geth_poa_middleware, layer=0)
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
    for i in range(1, n):
        result = result*x + poly[i]
    return result

class MyController_auth(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController_auth, self).__init__(*args, **kwargs)
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
        data = rsu_conn.recv(1024).decode() # got HPW, NVID, TID of reg
        auth_cont_instance = w3.eth.contract(address = auth_sc_address, abi = auth_abi) # creates an instance of handover contract
        reg_cont_instance = w3.eth.contract(address = reg_sc_address, abi = reg_abi) # creates an instance of init auth contract

        value1 = [str(i) for i in data.split('#')]
        rA = value1[3]
        auth1_start_latency = time.time ()
        auth1_comp_start_time = time.time ()

        T1 = get_timestamp()
        get_T1 = float(value1[4])
    

        if T1 - get_T1 < 4 :
            auth_nonce = w3.eth.get_transaction_count(acct_address)
            '''
            #check_TID = w3.eth.get_transaction(value1[2])
            # print ("check_TID is ", check_TID)
            #tid_BC_hash = check_TID.__dict__["hash"].hex()

            #if tid_BC_hash ==  value1[2]:
            # print ("Transaction happened for Reg")
            '''
            get_HPW_data = reg_cont_instance.functions.retrieve_reg_details(value1[0]).call() # run 
            if get_HPW_data[0] == value1[1] :
                    t_x = get_HPW_data[1] # list with const as 1st term
                    poly_deg = get_HPW_data[2] 
                    alpha = random.randint(2, 100) # 43

                    s = random.randint(2, 100) # 37
                    t_x_org = t_x[::-1] # largest pwer's coeff 1st 
                    g_alpha_s_i = []
                    g_s_i = []
                    g_alpha = int(pow(g, alpha, n))

                    for i in range(0,poly_deg+1):
                        g_s_i.append(int(pow(g, (s**i), n)))
                        g_alpha_s_i.append( int(pow(g, alpha *(s**i), n)))

                    t_s_np = np.poly1d(t_x_org) #reverse()) 
                    tx_val_on_s = horner (t_x_org, len(t_x_org), s) # subst s in t(x)
                    T2 = get_timestamp ()
                    msg1 = rA + "&"+ listToString(g_s_i) + "&"+ listToString(g_alpha_s_i) +"&"+ str(T2)
                    auth1_comp_end_time = time.time ()
                    auth_comp_time = auth1_comp_end_time - auth1_comp_start_time

                    rsu_conn.send(msg1.encode('utf')) # sending proving key to RSU
                    proof = rsu_conn.recv(1024).decode() # Get proof from RSU
                    proof1 = [i for i in proof.split(',')]
                    print ("^^^ Proof from Veh is ", proof1) 
                    proof = []
                    auth2_comp_start_time = time.time ()
                    proof.append (int(proof1[0]))
                    proof.append (int(proof1[1]))
                    proof.append (int(proof1[2]))
                    print ("============================")
                    print ("g^p is ", proof[0])
                    print ("g^h is ", proof[1])
                    print ("g^p` is ", proof[2])
                    
                    print ("Alpha is ", alpha)
                    print ("G^alpha is ", g_alpha)
                    print ("t(s) is ", tx_val_on_s)
                    print ("================================")
                    if rA == proof1[3] and get_timestamp() - float(proof1[4]) < 3 :

                        if proof[2] == int(pow(proof[0], alpha, n)): # e(g^p', g) = e(g^p, g^alpha)
                            print (" ----- First proof successful")
                            final_res = int(pow(proof[1], tx_val_on_s, n)) # (g_h * g_t_s_val) % n
                            if proof[0] == final_res:
                                print ("---- Second proof successful")
                                rA_auth = random.randint(100, 100000)
                                t = time.localtime()

                                new_NVID =  sha256(get_HPW_data[0].encode('utf-8') + str(t).encode('utf-8') + str(rA_auth).encode('utf-8')).hexdigest()
                                auth2_comp_end_time = time.time ()
                                auth_comp_time += auth2_comp_end_time - auth2_comp_start_time

                                ver_key = [g_alpha, tx_val_on_s]

                                auth1_end_latency = time.time ()

                                auth_latency = auth1_end_latency - auth1_start_latency
                                # Store HPW, new_NVID, rand_Auth, proof, Cv,   0,  ver_key
                                # str      ,  str    ,  int     , list , int, int, list 
                                BC_start_latency = time.time ()
                                call_function = auth_cont_instance.functions.store_auth_details(value1[0], new_NVID, rA_auth, get_HPW_data[3], 0, ver_key).build_transaction({"chainId": Chain_id, "from": acct_address, "nonce": auth_nonce, "gasPrice": w3.to_wei(2, 'gwei')})
                                signed_tx = w3.eth.account.sign_transaction(call_function, private_key = private_key)

                                send_tx = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                                tx_receipt = w3.eth.wait_for_transaction_receipt(send_tx)
        
                                Tx_ID = tx_receipt.__dict__["transactionHash"].hex()
                                BC_end_latency = time.time ()
                                print("Tx hash is ", Tx_ID)   
                                
                                auth2_start_latency = time.time ()
                                send_tid = Tx_ID + ","+ str(rA_auth) +","+ new_NVID +","+ str(rA) +","+ str(get_timestamp()) 
                                rsu_conn.send(send_tid.encode('utf')) # send TID, rA_auth, new_NVID, rA, T3
                                auth2_end_latency = time.time ()
                                auth_latency += auth2_end_latency - auth2_start_latency

                                sheet1 = pe.get_sheet (file_name = "Mani_SDN_auth_latency.xlsx")
                                sheet1.row += [tx_receipt.__dict__['gasUsed'], BC_end_latency - BC_start_latency, auth_latency, auth_comp_time]
                                sheet1.save_as ("Mani_SDN_auth_latency.xlsx")
                                
                                print ("AUthentication successful ...\n********* Done *********\n")
                            else :
                                print ("Second proof invalid")
                        else :
                            print ("First proof invalid")   
                    else :
                        print ("rA does not match or time stamp check failed ....")
            else :
                print ("NVID does not match from BC ...")
        else :
            print ("Time stamp check failed ... Possible session key attack")
      
        print ("------------------------")
        # print_lock.release() # n
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
        cfg.IntOpt('controller1_port', default=6633,
                   help='OpenFlow controller port for App1'),
    ])

    utils.load_modules(['MyController_auth'])
    app_manager.run()
