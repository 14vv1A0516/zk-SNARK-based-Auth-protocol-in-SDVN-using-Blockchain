
import socket
import random # import randint 
import time
import collections
import hashlib
from hashlib import sha256
import sys
import numpy as np
import hashlib

from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import time
import datetime
from ecdsa import SECP256k1, VerifyingKey
import pyexcel as pe 

class Present:
    def __init__(self, key, rounds=32):
        """Create a PRESENT cipher object

        key:    the key as a 128-bit or 80-bit rawstring
        rounds: the number of rounds as an integer, 32 by default
        """
        self.rounds = rounds
        if len(key) * 8 == 80:
            self.roundkeys = generateRoundkeys80(string2number(key), self.rounds)
        elif len(key) * 8 == 128:
            self.roundkeys = generateRoundkeys128(string2number(key), self.rounds)
        else:
            raise ValueError ("Key must be a 128-bit or 80-bit rawstring")

    def present_encrypt(self, block):
        """Encrypt 1 block (8 bytes)

        Input:  plaintext block as raw string
        Output: ciphertext block as raw string
        """
        state = string2number(block)
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[i])
            state = sBoxLayer(state)
            state = pLayer(state)
        cipher = addRoundKey(state, self.roundkeys[-1])
        #print ("cipher text  is ", cipher, "and type is ", type(cipher))
        return number2string_N(cipher, 8)

    def present_decrypt(self, block):
        """Decrypt 1 block (8 bytes)

        Input:  ciphertext block as raw string
        Output: plaintext block as raw string
        """
        state = string2number(block)
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[-i - 1])
            state = pLayer_dec(state)
            state = sBoxLayer_dec(state)
        decipher = addRoundKey(state, self.roundkeys[0])
        return number2string_N(decipher, 8)

    def get_block_size(self):
        return 8

# 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
Sbox_inv = [Sbox.index(x) for x in range(16)]
PBox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]
PBox_inv = [PBox.index(x) for x in range(64)]

def generateRoundkeys80(key, rounds): # PRESENT cipher funct
    roundkeys = []
    for i in range(1, rounds + 1):  # (K1 ... K32)
        # rawkey: used in comments to show what happens at bitlevel
        # rawKey[0:64]
        roundkeys.append(key >> 16)
        # 1. Shift
        # rawKey[19:len(rawKey)]+rawKey[0:19]
        key = ((key & (2 ** 19 - 1)) << 61) + (key >> 19)
        # 2. SBox
        # rawKey[76:80] = S(rawKey[76:80])
        key = (Sbox[key >> 76] << 76) + (key & (2 ** 76 - 1))
        #3. Salt
        #rawKey[15:20] ^ i
        key ^= i << 15
    print ("80 bit round keys are ", roundkeys)
    return roundkeys

def generateRoundkeys128(key, rounds):  # PRESENT cipher funct
    roundkeys = []
    for i in range(1, rounds + 1):  # (K1 ... K32)
        # rawkey: used in comments to show what happens at bitlevel
        roundkeys.append(key >> 64)
        # 1. Shift
        key = ((key & (2 ** 67 - 1)) << 61) + (key >> 67)
        # 2. SBox
        key = (Sbox[key >> 124] << 124) + (Sbox[(key >> 120) & 0xF] << 120) + (key & (2 ** 120 - 1))
        key ^= i << 62
    return roundkeys


def addRoundKey(state, roundkey): # PRESENT cipher funct
    return state ^ roundkey


def sBoxLayer(state): 
    output = 0
    for i in range(16):
        output += Sbox[( state >> (i * 4)) & 0xF] << (i * 4)
    return output


def sBoxLayer_dec(state): 
    output = 0
    for i in range(16):
        output += Sbox_inv[( state >> (i * 4)) & 0xF] << (i * 4)
    return output


def pLayer(state):  
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << PBox[i]
    return output


def pLayer_dec(state):  
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << PBox_inv[i]
    return output


def string2number(i):
    return int(i, 16)


def number2string_N(i, N): 
    s = '%0*x' % (N * 2, i)
    return str(s)


def _test():
    import doctest

    doctest.testmod()

# =======================PRESENT cipher Over ===============

def listToString(s):  # General dunct
 
    str1 = ""
    for ele in s:
        str1 += str(ele)
        str1 += ","
    str1 = str1[:len(str1)-1]
    return str1

def convertTuple_str(tup):  #  General funct
    dh_str = ''
    for item in tup:
        dh_str = dh_str + str(item) + ","
    return dh_str


EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)

def inverse_mod(k, p): # ECC funct
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p

# Functions that work on curve points #########################################

def is_on_curve(point):  # ECC funct
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):  # ECC funct
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result

def point_add(point1, point2):  # ECC funct
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        return point2
    if point2 is None:
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2:
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result

def scalar_mult(k, point):   # ECC funct
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result

def make_keypair(): # ECC funct
    private_key = random.randrange(1, curve.n) 
    public_key = scalar_mult(private_key, curve.g)
    return private_key, public_key

def encrypt_data (cipher, plain_text) :
    encrypted_1 = []
    plain_text = plain_text.encode().hex()
    if len(plain_text) > 16 :
        splitted_pt = [plain_text[i:i+16] for i  in range(0, len(plain_text), 16)]
        for each_str in splitted_pt:
            encrypted_1.append(cipher.present_encrypt(each_str))
    else :
        encrypted_1 = cipher.present_encrypt(plain_text)
    
    return listToString(encrypted_1)

def decrypt_data (cipher, enc_text) :

    decrypted_1 = []
    splitted_pt = [str(i) for i in enc_text.split(',')]
    for each_str in splitted_pt:
        decrypted_1.append(bytes.fromhex(cipher.present_decrypt(each_str) ).decode())
    decrypt_temp = ""
    decrypted_1 = decrypt_temp.join(decrypted_1)
    decrypted_1 = decrypted_1.rstrip('\x00').replace('\x00', '')
    
    return decrypted_1

def get_timestamp() :
    ct = datetime.datetime.now() 
    ts = ct.timestamp()
    return ts

host = "11.0.0.100" # socket.gethostname() 11.0.0.100
print("Host IP is ", host)
port = 6012  # initiate port no above 1024

veh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # instantiate

flag = 0

while flag == 0 :
    try :
        veh_socket.connect((host, port))  # connect to the RSU
        flag = 1
    except :
        print ("Failed to connect ...")

print ("-------------------------------\n")

TA_ver_key = 'd92d4d388c6963b9c15a9820f3f7e3289a6d084d2fdcc3c27bd34ab2df5f4f3de29b0281273473bdba8a2159a097101b304a26cd69d623c35d2a0d5ba649bcb5'

TA_ver_key_bytes = bytes.fromhex (TA_ver_key)
TA_ver_key = VerifyingKey.from_string(TA_ver_key_bytes, curve=SECP256k1)

veh_key_obj = generate_eth_key()
veh_pri_key = veh_key_obj.to_hex() # secret
veh_pub_key = veh_key_obj.public_key.to_hex() # format(True)

auth_req = '02,' + veh_pub_key # veh_pub_key
veh_socket.send(auth_req.encode('utf'))  # send auth_req to RSU

get_sign = veh_socket.recv(1024)# .decode()  # receive ID and signature

get_sign = decrypt(veh_pri_key, get_sign) # .encode('utf-8'))
# --- verify signature
get_sign = get_sign.decode()

values = [str(i) for i in get_sign.split('#')] # TA_signature, SDN_ID, RSU_ID, RSU_pub_key, rsu_rand

TA_signature = bytes.fromhex(values[0]) # hex to bytes
SDN_ID = values[1]
RSU_ID = values[2]
RSU_pub_key = values[3]
rsu_rand = values[4]
hsdnrsu = values[5]

print ("TA ver key is ", TA_ver_key)

print ("TA signture is ", TA_signature)
print ("SDN ID is ", SDN_ID)
print ("RSU ID is ", RSU_ID)

# RSU_pub_key = RSU_pub_key.encode().hex()

is_valid = TA_ver_key.verify(TA_signature, hsdnrsu.encode())

print ("is valid : ", is_valid)
# verify_signature(TA_pub_key, bytes(RSU_reg_msg, 'utf-8'), TA_signature)
if is_valid == True :

    veh_dh_pri_key, dh_open_key = make_keypair()

    dh_open_key = convertTuple_str(dh_open_key)

    rv = random.randint(100, 100000)
    msg2 = str(rv)+ "#"+ dh_open_key
    

    msg2 = encrypt(RSU_pub_key, msg2.encode('utf-8'))
    veh1_comp_end_time = time.time ()

    veh_socket.send(msg2)  # send dh_open key to RSU

    data = veh_socket.recv(1024)

    data = decrypt (veh_pri_key, data)
    data = data.decode()

    values = [str(i) for i in data.split('#')]

    if values[0] == str(rv) :
        print ("rv matched, Diffie helman starts ...")
        values = [str(i) for i in values[1].split(',')]

        RSU_dh_open_key = (int(values[0]), int(values[1]))

        s1 = scalar_mult(veh_dh_pri_key, RSU_dh_open_key)
        print ("----\n", convertTuple_str(s1))

        final_int = s1[0] ^ s1[1]

        hash_of_key = hashlib.sha256(str(final_int).encode())
        # print('Shared secret: (0x{:x}, 0x{:x})'.format(*s1))
        final_symmetric_key = hash_of_key.hexdigest()
        print ("Final shared key is ", final_symmetric_key, "and type is ", type(final_symmetric_key))

        print ("*******************************************\n")

        # -------- Got final ECDH key ------------------------
                                                                                                                                                                                                                                     
        key = final_symmetric_key[:16] # "0123456789123456" # .decode('hex')

        cipher = Present(key)

        # ------ Handover Authentication starts now ---------------
        veh_id = sys.argv[1] # '0C4REMZ'
        veh_pswd = sys.argv[2] # 'krishna'
        veh1_comp_start_time = time.time ()

        HPW = sha256(veh_id.encode('utf-8') + veh_pswd.encode('utf-8')).hexdigest()
        print ("HPW is ", HPW)

        #HPW = sha256(sys.argv[1].encode('utf-8') + sys.argv[2].encode('utf-8')).hexdigest() # veh_id , Veh_pswd
        reg_sheet = pe.get_sheet(file_name="ZKP_Auth_details.xlsx")
        reg_flag = 0
        for row in reg_sheet :
            if row[0] == HPW :
               reg_flag = 1 
               print ("HPW match found ...")
               break

        if reg_flag == 1 :
            # HPW, new_NVID, rA_AUth, Tx_ID, T1
            T1 = get_timestamp()
            msg1 = row[0]+ "#"+ row[3] +"#"+ row[2] +"#"+ row[1] +"#"+ str(T1)    
            
            enc_msg1 = encrypt_data (cipher, msg1)
            veh1_comp_end_time = time.time ()
            veh_hand_comp_time = veh1_comp_end_time - veh1_comp_start_time

            veh_socket.send(enc_msg1.encode('utf')) # send HPW, NVID, TID
            rh = veh_socket.recv(1024).decode() # new_NVID, rh, T1

            veh2_comp_start_time = time.time ()
            rh_values = decrypt_data (cipher, rh)
            rh_values = [str(i) for i in rh_values.split(',')]
            if get_timestamp() - float(rh_values[2]) < 4 and row[3] == rh_values[0] : 
                
                proof_msg2 = row[6] +"&"+ rh_values[1] +"&"+ str(get_timestamp ())
                print ("Prrof msg is ", proof_msg2)
                
                enc_msg2 = encrypt_data (cipher, proof_msg2)
                veh2_comp_end_time = time.time () 

                veh_hand_comp_time += veh2_comp_end_time - veh2_comp_start_time

                veh_socket.send(enc_msg2.encode('utf')) # sending proof, rh, T2

                session_key = veh_socket.recv(1024).decode()

                session_key = decrypt_data (cipher, session_key)

                print (" ****** Total Veh Handover comp time is ", veh_hand_comp_time, " sec")
                sheet1 = pe.get_sheet(file_name = "Mani_Hand_Veh_comp_time.xlsx")

                sheet1.row += [veh_hand_comp_time ]
                sheet1.save_as ("Mani_Hand_Veh_comp_time.xlsx")  
                print ("Got the session key .....\n Handover Authentication Successful ....")

            else :
                print ("rh does not match or Time Stamp check failed ...")
        else :
            print ("HPW not found in sheet ...")
    else :
        print ("Rv  does not match, Diffi helman failed ...")
else :
    print ("TA signature failed to be verified ...")

veh_socket.close()


# print ("decrypted text from RSU is ", get_decrypt)


