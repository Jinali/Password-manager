from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import base64
import sys
import os
import binascii



class CTRMode:
    def __init__(self):

        # Pick randome 64-bit nonce
        self.nonce = Random.new().read(8)
        # 32-bit private key
        self.key = 'youcantseemehahahahajiniqueen!!!'


    def encrypt(self, plaintext):
        encryptor = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(64, prefix=self.nonce))
        ciphertext = base64.b64encode(encryptor.encrypt(plaintext))
        return ciphertext


    # ciphertext and nonce are taken from file
    def decrypt(self, ciphertext, nonce):
        decryptor = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
        plaintext = decryptor.decrypt(base64.b64decode(ciphertext))
        return plaintext


    def checkerusernamepassword(self, plaintext):
        file = []
        dict={}

        for f_lines in open('./ctr_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)

        for line in file:
            e_username, e_password, nonce = line.split(':')
            username = self.decrypt(e_username, nonce)
            password = self.decrypt(e_password, nonce)
            dict[username] = password                                                   

        if dict.has_key(plaintext) == True:
            print "duplicate user found"
            sys.exit(0)


    def checksumdatabase(self):
        # If file does not exist then create it
        if os.path.exists('./ctr_db'):
            pass
        else:
           fo = open('./ctr_db', 'w')
           fo.close() 





