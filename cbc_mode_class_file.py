from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import base64
import sys
import os
import binascii



class CBCMode:
    def __init__(self):

        # 32-bit private key
        self.key = 'youcantseemehahahahajiniqueen!!!'
        self.block_size = 16
        self.iv = os.urandom(16)



    def encrypt(self, plaintext):
        encrypt_mode = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = base64.b64encode(self.iv + encrypt_mode.encrypt((self.padding(plaintext))))
        return ciphertext


    def decrypt(self, ciphertext, iv):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        encrypt_mode = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = self.unpad(encrypt_mode.decrypt(ciphertext[AES.block_size:]))
        return plaintext


    def checkerusernamepassword(self, plaintext):
        file = []
        dict={}

        for f_lines in open('./cbc_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)

        for line in file:
            e_username, e_password, iv = line.split(':')
            username = self.decrypt(e_username, iv)
            password = self.decrypt(e_password, iv)
            dict[username] = password                                                   

        if dict.has_key(plaintext) == True:
            print "duplicate user found"
            sys.exit(0)



    def padding(self, plaintext):
        return plaintext + (((16-len(plaintext) % 16)) * '\x00')


    def unpad(self, plaintext):
        return plaintext.rstrip(b'\x00')


    def checksumdatabase(self):
        # If file does not exist then create it
        if os.path.exists('./cbc_db'):
            pass
        else:
           fo = open('./cbc_db', 'w')
           fo.close() 




