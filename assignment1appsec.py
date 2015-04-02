import argparse
import base64
import sys
import os
from ctr_mode_class_file import *
from cbc_mode_class_file import *
from ecb_mode_class_file import *

# user guidance
parser = argparse.ArgumentParser()
parser.add_argument('-username', dest='username', help='Enter username')
parser.add_argument('-password', dest='password', help='Enter password')
parser.add_argument('-encryption', action='store_true', help='Execute action encryption')
parser.add_argument('-decryption', action='store_true', help='Execute action decryption')
parser.add_argument('-ecb', action='store_true', help='get into ecb mode')
parser.add_argument('-cbc', action='store_true', help='get into cbc mode')
parser.add_argument('-ctr', action='store_true', help='get into ctr mode')

args=parser.parse_args()

# setting flag
flag = False
if args.ecb:
    c_ecb = args.ecb
    flag = True
if args.ctr:
    c_ctr = args.ctr
    flag = True
if args.cbc:
    c_cbc = args.cbc
    flag = True

if flag == False:
    print "[-] encryption mode required"
    sys.exit(0)

# Encryption modes
if args.encryption:
    if args.username == None:
        print "[-] username required "
        sys.exit(0)

    if args.password == None:
        print "[-] password required "
        sys.exit(0)



    # CTR_mode
    if args.ctr:
        
        ctr = CTRMode()

        # check if db file exists
        ctr.checksumdatabase()


        plaintext = args.username
        ctr.checkerusernamepassword(plaintext)   # verify if duplicate username exists
        e_username = ctr.encrypt(plaintext)
                    
        plaintext = args.password
        e_password = ctr.encrypt(plaintext)

        fo = open('ctr_db', 'a')   
        fo.write(('%s : %s : %s') % (e_username, e_password, ctr.nonce))
        fo.write('\n')
        fo.close()




    # CBC
    if args.cbc:
        cbc = CBCMode()

        # check if db file exists
        cbc.checksumdatabase()


        plaintext = args.username
        cbc.checkerusernamepassword(plaintext)   # verify if duplicate username exists
        e_username = cbc.encrypt(plaintext)

        plaintext = args.password
        e_password = cbc.encrypt(plaintext)

        fo = open('cbc_db', 'a')
        fo.write(('%s : %s : %s') % (e_username, e_password, cbc.iv))
        fo.write('\n')
        fo.close()




    # ECB
    if args.ecb:
        ecb = ECBMode()

        # check if db file exists
        ecb.checksumdatabase()


        plaintext = args.username
        ecb.checkerusernamepassword(plaintext)   # verify if duplicate username exists
        e_username = ecb.encrypt(plaintext)

        plaintext = args.password
        e_password = ecb.encrypt(plaintext)

        fo = open('ecb_db', 'a')
        fo.write(('%s : %s') % (e_username, e_password))
        fo.write('\n')
        fo.close()

# Decrypt
if args.decryption:

    # CTR_mode 
    if args.ctr:
        
        ctr = CTRMode()


        plaintext = args.username
        file = []
        dict={}

        for f_lines in open('./ctr_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)


        for line in file:
            e_username, e_password, nonce = line.split(':')
            username = ctr.decrypt(e_username, nonce)
            password = ctr.decrypt(e_password, nonce)
            dict[username] = password


        if dict.has_key(plaintext) == True:
            print dict[plaintext]
        else:
            print "no user found"




    # CBC
    if args.cbc:
        # Instantiate ctr from CTR() class: "ctr_class"
        cbc = CBCMode()

        plaintext = args.username
        file = []
        dict={}


        for f_lines in open('./cbc_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)        


        for line in file:
            e_username, e_password, iv = line.split(':')
            username = cbc.decrypt(e_username, iv)
            password = cbc.decrypt(e_password, iv)
            dict[username] = password


        if dict.has_key(plaintext) == True:
            print dict[plaintext]
        else:
            print "no user found"




    # ECB
    if args.ecb:
        # Instantiate ctr from CTR() class: "ctr_class"
        ecb = ECBMode()

        plaintext = args.username
        file = []
        dict={}

        for f_lines in open('./ecb_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)        

        for line in file:
            e_username, e_password = line.split(':')
            username = ecb.decrypt(e_username)
            password = ecb.decrypt(e_password)
            dict[username] = password


        if dict.has_key(plaintext) == True:
            print dict[plaintext]
        else:
            print "no user found"
