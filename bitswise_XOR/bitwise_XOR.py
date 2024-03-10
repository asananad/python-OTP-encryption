import numpy as np
import os, sys, hashlib

def keygen_number(): 
    key_list = []
    if sys.argv[2] == "-file" or "-f":
        file = open(sys.argv[3], "rb")
        byte_buffer = file.read()
        for x in range(len(byte_buffer)):
            key_list.append(ord(os.urandom(1)))
        f = open(sys.argv[4] + ".key", 'wb')
    else:
        for x in range(int(sys.argv[2])):
            key_list.append(ord(os.urandom(1)))
        f = open(sys.argv[3] + ".key", 'wb')
    f.write(bytes(key_list))
    f.close()
    print("\n Keyfile created.\n")

def encrypt():
    file = open(sys.argv[2], "rb")
    byte_list = file.read()
    byte_list2 = []
    for x in byte_list:
        byte_list2.append(x)

    file2 = open(sys.argv[3], "rb")
    key_list = file2.read()
    key_list2 = []
    for x in key_list:
        key_list2.append(x)
    
    key_list2 = key_list2[:len(byte_list2)]

    result_list = np.bitwise_xor(byte_list2, key_list2).tolist()
    
    f = open(sys.argv[2] + ".enc", 'wb')
    f.write(bytes(result_list))
    f.close()

def decrypt():
    file = open(sys.argv[2], "rb")
    byte_list = file.read()
    byte_list2 = []
    for x in byte_list:
        byte_list2.append(x)

    file2 = open(sys.argv[3], "rb")
    key_list = file2.read()
    key_list2 = []
    for x in key_list:
        key_list2.append(x)
    
    key_list2 = key_list2[:len(byte_list2)]

    result_list = np.bitwise_xor(byte_list2, key_list2).tolist()
    
    f = open(sys.argv[2].replace(".enc", ".dec"), 'wb')
    f.write(bytes(result_list))
    f.close()

def generate_checksum(file_to_checksum):
    f_to_checksum_bytes = open(file_to_checksum, "rb").read()
    checksum = hashlib.sha512(f_to_checksum_bytes).hexdigest()
    return checksum

def check_checksum(checksum):
    file = open((sys.argv[2]), "rb").read()
    checksum_file = open((sys.argv[3]), "r").read()
    checksum = hashlib.sha512(file).hexdigest()
    print("\n " + checksum_file + "\n " + checksum + "\n")
    if checksum == checksum_file :
        return(True)
    else:
        return(False)

def generate_checksum_file(file_to_checksum, path_checksum_file):
    fullpath_checksum_file = path_checksum_file + ".sha512"
    f_to_checksum_bytes = open(file_to_checksum, "rb").read()
    checksum = hashlib.sha512(f_to_checksum_bytes).hexdigest()
    checksum_file = open(fullpath_checksum_file, "x")
    checksum_file.write(checksum)
    checksum_file.close()
    return fullpath_checksum_file

def check_checksum_file():
    file = open((sys.argv[2]), "rb").read()
    checksum_file = open((sys.argv[3]), "r").read()
    checksum = hashlib.sha512(file).hexdigest()
    print("\n " + checksum_file + "\n " + checksum + "\n")
    if checksum == checksum_file :
        return(True)
    else:
        return(False)