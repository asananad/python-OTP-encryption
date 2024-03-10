import sys
import secrets
import hashlib
from tqdm import tqdm

########## Key generation function and generating checksum ##########
def generate_key():
    iterations = int(sys.argv[2]) * 2
    filename_key = sys.argv[3]
    f = open(filename_key, "x")
    buffer_randomnum = ""
    print("")
    for x in tqdm(range(iterations),desc=" Progress: "):
        random_number = secrets.SystemRandom().randint(0, 9)
        random_number = str(random_number)
        buffer_randomnum = buffer_randomnum + random_number
    buffer_randomnum = "\n".join(buffer_randomnum[i:i + 60] for i in range(0, len(buffer_randomnum), 60))
    buffer_randomnum_array = buffer_randomnum.splitlines(True)
    definitive = ""
    for x in buffer_randomnum_array :
        definitive = definitive + "   ".join(x[i:i + 5] for i in range(0, len(x), 5))
    f.write(definitive)
    f.close()
    print("\n The key file has been created.")
    f_to_checksum = open(filename_key, "r").read()
    checksum = hashlib.sha512((f_to_checksum).encode('utf-8')).hexdigest()
    f2 = open((filename_key + ".sha512"), "x")
    f2.write(checksum)
    print("\n The sha512 checksum file has been created.\n")
#############################################

######### Encrypting textfile function and generating checksum ##########
def encrypt():
    textfile_encrypt = open((sys.argv[2]), "r").read()
    keyfile_encrypt = open((sys.argv[3]), "r").read()
    keyfile_encrypt = keyfile_encrypt.replace("\n", "")
    keyfile_encrypt = keyfile_encrypt.replace(" ", "")
    charset = {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5, 'f': 6, 'g': 7, 'h': 8, 'i': 9, 'j': 10, 'k': 11, 'l': 12, 'm': 13, 'n': 14, 'o': 15, 'p': 16, 'q': 17, 'r': 18, 's': 19, 't': 20, 'u': 21, 'v': 22, 'w': 23, 'x': 24, 'y': 25, 'z': 26, 'A': 27, 'B': 28, 'C': 29, 'D': 30, 'E': 31, 'F': 32, 'G': 33, 'H': 34, 'I': 35, 'J': 36, 'K': 37, 'L': 38, 'M': 39, 'N': 40, 'O': 41, 'P': 42, 'Q': 43, 'R': 44, 'S': 45, 'T': 46, 'U': 47, 'V': 48, 'W': 49, 'X': 50, 'Y': 51, 'Z': 52, '0': 53, '1': 54, '2': 55, '3': 56, '4': 57, '5': 58, '6': 59, '7': 60, '8': 61, '9': 62, ' ': 63, '!': 64, '"': 65, '#': 66, '$': 67, '%': 68, '&': 88, "'": 70, '(': 71, ')': 72, '*': 73, '+': 74, ',': 75, '-': 76, '.': 77, '/': 78, ':': 79, ';': 80, '<': 81, '=': 82, '>': 83, '?': 84, '@': 85, '[': 86, '\\': 87, ']': 89, '^': 90, '_': 91, '`': 92, '{': 93, '|': 94, '}': 95, '~': 96, '\n': 97}
    numbered_text = []
    print("")
    for x in tqdm(textfile_encrypt, total=len(textfile_encrypt),desc=" Step 1: "):
        if x in charset:
            numbered_text.append(charset[x])
        else:
            print("\n Wrong character detected, use only the basic set of ASCII characters in plaintext.")
    output_text = ""
    i = 0
    print("")
    for x in tqdm(numbered_text, total=len(numbered_text),desc=" Step 2: "):
        temporary_number_text = keyfile_encrypt[i] + keyfile_encrypt[i + 1]
        temporary_number = int(temporary_number_text)
        if x + temporary_number >= 100:
            output_text_add = str(x + temporary_number - 100)
            if int(output_text_add) < 10:
                output_text_add = "0" + output_text_add
        elif x + temporary_number < 10:
            output_text_add = "0" + str(x + temporary_number)
        else:
             output_text_add = str(x + temporary_number)
        output_text = output_text + output_text_add
        i = i + 2
    output_text = "\n".join(output_text[i:i + 60] for i in range(0, len(output_text), 60))
    output_text_array = output_text.splitlines(True)
    definitive = ""
    print("")
    for x in tqdm(output_text_array, total=len(output_text_array),desc=" Step 3: "):
        definitive = definitive + "   ".join(x[i:i + 5] for i in range(0, len(x), 5))
    name_of_enc_file = sys.argv[2] + ".enc"
    f = open((name_of_enc_file), "x")
    f.write(definitive)
    f.close()
    print("\n The encrypted file has been created.\n")
    f_to_checksum = open(name_of_enc_file, "r").read()
    checksum = hashlib.sha512((f_to_checksum).encode('utf-8')).hexdigest()
    f2 = open((name_of_enc_file + ".sha512"), "x")
    f2.write(checksum)
    print(" The sha512 checksum file has been created.\n")
#################################################


########## Decrypting textfile function ##########
def decrypt():
    textfile_decrypt = open((sys.argv[2]), "r").read()
    keyfile_decrypt = open((sys.argv[3]), "r").read()
    keyfile_decrypt = keyfile_decrypt.replace("\n", "")
    keyfile_decrypt = keyfile_decrypt.replace(" ", "")
    textfile_decrypt = textfile_decrypt.replace("\n", "")
    textfile_decrypt = textfile_decrypt.replace(" ", "")
    charset = {1: 'a', 2: 'b', 3: 'c', 4: 'd', 5: 'e', 6: 'f', 7: 'g', 8: 'h', 9: 'i', 10: 'j', 11: 'k', 12: 'l', 13: 'm', 14: 'n', 15: 'o', 16: 'p', 17: 'q', 18: 'r', 19: 's', 20: 't', 21: 'u', 22: 'v', 23: 'w', 24: 'x', 25: 'y', 26: 'z', 27: 'A', 28: 'B', 29: 'C', 30: 'D', 31: 'E', 32: 'F', 33: 'G', 34: 'H', 35: 'I', 36: 'J', 37: 'K', 38: 'L', 39: 'M', 40: 'N', 41: 'O', 42: 'P', 43: 'Q', 44: 'R', 45: 'S', 46: 'T', 47: 'U', 48: 'V', 49: 'W', 50: 'X', 51: 'Y', 52: 'Z', 53: '0', 54: '1', 55: '2', 56: '3', 57: '4', 58: '5', 59: '6', 60: '7', 61: '8', 62: '9', 63: ' ', 64: '!', 65: '"', 66: '#', 67: '$', 68: '%', 88: '&', 70: "'", 71: '(', 72: ')', 73: '*', 74: '+', 75: ',', 76: '-', 77: '.', 78: '/', 79: ':', 80: ';', 81: '<', 82: '=', 83: '>', 84: '?', 85: '@', 86: '[', 87: '\\', 89: ']', 90: '^', 91: '_', 92: '`', 93: '{', 94: '|', 95: '}', 96: '~', 97: '\n'}
    output_text = ""
    output_text_pre = []
    i = 0
    iterations = len(textfile_decrypt)
    print("")
    for x in tqdm(range(int(iterations / 2)),desc=" Step 1: "):
        temporary_number_text = textfile_decrypt[i] + textfile_decrypt[i + 1]
        temporary_number = int(temporary_number_text)
        temporary_number_key_text = keyfile_decrypt[i] + keyfile_decrypt[i + 1]
        temporary_number_key = int(temporary_number_key_text)
        calculated = temporary_number - temporary_number_key
        if calculated < 0:
            calculated = calculated + 100
        output_text_add = calculated
        output_text_pre.append(output_text_add)
        i = i + 2
    print("")
    for x in tqdm(output_text_pre, total=len(output_text_pre),desc=" Step 2: "):
        if x in charset:
            output_text = output_text + charset[x]
    name_of_dec_file = sys.argv[2].replace(".enc", "")
    f = open((name_of_dec_file + ".dec"), "x")
    f.write(output_text)
    f.close()
    print("\n The decrypted file has been created.\n")

##################################################

########## Checksum function ##########
def checksum():
    file = open((sys.argv[2]), "r").read()
    checksum_file = open((sys.argv[3]), "r").read()
    checksum = hashlib.sha512((file).encode('utf-8')).hexdigest()
    print("\n " + checksum_file + "\n " + checksum + "\n")
    if checksum == checksum_file :
        print("\n - SUCCESS -   The checksum matches\n")
    else:
        print("\n - FAILED -   The checksum does NOT match\n")
#######################################

############### Main ###############
if sys.argv[1] == "keygen" and isinstance(int(sys.argv[2]), int) and isinstance(sys.argv[3], str):
    generate_key()
elif sys.argv[1] == "encrypt" and isinstance(str(sys.argv[2]), str) and isinstance(sys.argv[3], str):
    encrypt()
elif sys.argv[1] == "decrypt" and isinstance(str(sys.argv[2]), str) and isinstance(sys.argv[3], str):
    decrypt()
elif sys.argv[1] == "checksum" and isinstance(str(sys.argv[2]), str) and isinstance(sys.argv[3], str):
    checksum()
elif sys.argv[1] == "help":
    print("\nThis program generates keys for the One Time Pad cipher, also encrypts and decrypts textfiles using the keys and generates and checks checksums.\nUse 'python3 OTP.py keygen lenght_of_key filename_or_path_to_save_key_to' for key generation.\nUse 'python3 OTP.py encrypt textfile_to_encrypt keyfile_to_use' to encrypt.\nUse 'python3 OTP.py decrypt textfile_to_decrypt keyfile_to_use' to decrypt.\nUse 'python3 OTP.py checksum file checksum_file' to perform the check.\nUse 'python3 OTP.py help' to show this help message.\n")
else:
    print("\nWrong arguments, enter 'python3 OTP.py help' for guidance on how to use this program.\n")
