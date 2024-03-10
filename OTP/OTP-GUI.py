import sys
import secrets
import hashlib
from tqdm import tqdm
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk

form = tk.Tk()
form.title("One Time Pad")
#form.iconbitmap("calc.ico")
#form.geometry("500x280")

tab_parent = ttk.Notebook(form)

tab1 = ttk.Frame(tab_parent)
tab2 = ttk.Frame(tab_parent)
tab3 = ttk.Frame(tab_parent)
tab4 = ttk.Frame(tab_parent)

tab_parent.add(tab1, text="Keygen")
tab_parent.add(tab2, text="Encrypt")
tab_parent.add(tab3, text="Decrypt")
tab_parent.add(tab4, text="Checksum")

def window_alert2(message):
    messagebox.showinfo("Alert", message)

# TAB ONE

########## Key generation function and generating checksum ##########
def generate_key():
    iterations = int(e_iterations.get()) * 2
    filename_key = (e_key.get() + ".txt")
    f = open(filename_key, "x")
    buffer_randomnum = ""
    for x in range(iterations):
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
    f_to_checksum = open(filename_key, "r").read()
    checksum = hashlib.sha512((f_to_checksum).encode('utf-8')).hexdigest()
    f2 = open(("key_checksum.txt"), "x")
    f2.write(checksum)
    window_alert2("Key file has been created.\nChecksum of key has been created.")
#############################################

label_iterations = Label(tab1, text="Lenght of key:")
label_iterations.grid(row=0, column=0)

label_key = Label(tab1, text="Name of key:")
label_key.grid(row=1, column=0)

button_keygen = Button(tab1, text="Generate key", padx=10, pady=7, command=generate_key)
button_keygen.grid(row=2, column=1)

e_iterations = Entry(tab1, width=25, font=("Calibri 11"))
e_iterations.grid(row=0, column=1, columnspan=3, padx=10, pady=10)

e_key = Entry(tab1, width=25, font=("Calibri 11"))
e_key.grid(row=1, column=1, columnspan=3, padx=10, pady=10)


# TAB TWO

######### Encrypting textfile function and generating checksum ##########
def encrypt():
    textfile_encrypt = open((e_textfile.get()), "r").read()
    keyfile_encrypt = open((e_keyfile.get()), "r").read()
    keyfile_encrypt = keyfile_encrypt.replace("\n", "")
    keyfile_encrypt = keyfile_encrypt.replace(" ", "")
    charset = {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5, 'f': 6, 'g': 7, 'h': 8, 'i': 9, 'j': 10, 'k': 11, 'l': 12, 'm': 13, 'n': 14, 'o': 15, 'p': 16, 'q': 17, 'r': 18, 's': 19, 't': 20, 'u': 21, 'v': 22, 'w': 23, 'x': 24, 'y': 25, 'z': 26, 'A': 27, 'B': 28, 'C': 29, 'D': 30, 'E': 31, 'F': 32, 'G': 33, 'H': 34, 'I': 35, 'J': 36, 'K': 37, 'L': 38, 'M': 39, 'N': 40, 'O': 41, 'P': 42, 'Q': 43, 'R': 44, 'S': 45, 'T': 46, 'U': 47, 'V': 48, 'W': 49, 'X': 50, 'Y': 51, 'Z': 52, '0': 53, '1': 54, '2': 55, '3': 56, '4': 57, '5': 58, '6': 59, '7': 60, '8': 61, '9': 62, ' ': 63, '!': 64, '"': 65, '#': 66, '$': 67, '%': 68, '&': 88, "'": 70, '(': 71, ')': 72, '*': 73, '+': 74, ',': 75, '-': 76, '.': 77, '/': 78, ':': 79, ';': 80, '<': 81, '=': 82, '>': 83, '?': 84, '@': 85, '[': 86, '\\': 87, ']': 89, '^': 90, '_': 91, '`': 92, '{': 93, '|': 94, '}': 95, '~': 96, '\n': 97}
    numbered_text = []
    for x in textfile_encrypt:
        if x in charset:
            numbered_text.append(charset[x])
        else:
            window_alert2("\n Wrong character detected, use only the basic set of ASCII characters in plaintext.")
    output_text = ""
    i = 0
    for x in numbered_text:
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
    for x in output_text_array:
        definitive = definitive + "   ".join(x[i:i + 5] for i in range(0, len(x), 5))
    name_of_enc_file = "encrypted_file.txt"
    f = open((name_of_enc_file), "x")
    f.write(definitive)
    f.close()
    f_to_checksum = open(name_of_enc_file, "r").read()
    checksum = hashlib.sha512((f_to_checksum).encode('utf-8')).hexdigest()
    f2 = open(("encrypted_file_checksum.txt"), "x")
    f2.write(checksum)
    window_alert2("The encrypted file has been created.\nThe sha512 checksum file has been created.")
#################################################

def open_textfile():
    filename_textfile =  filedialog.askopenfilename(initialdir = "/",title = "Select file")
    e_textfile.delete(0, END)
    e_textfile.insert(0, filename_textfile)

def open_keyfile():
    filename_keyfile =  filedialog.askopenfilename(initialdir = "/",title = "Select file")
    e_keyfile.delete(0, END)
    e_keyfile.insert(0, filename_keyfile)


button_textfile = Button(tab2, text="Select Textfile", padx=0, pady=0, command=open_textfile)
button_textfile.grid(row=0, column=0)

button_keyfile = Button(tab2, text="Select Keyfile", padx=0, pady=0, command=open_keyfile)
button_keyfile.grid(row=1, column=0)

button_encrypt = Button(tab2, text="Encrypt", padx=10, pady=7, command=encrypt)
button_encrypt.grid(row=2, column=1)

e_textfile = Entry(tab2, width=25, font=("Calibri 11"))
e_textfile.grid(row=0, column=1, columnspan=3, padx=10, pady=10)

e_keyfile = Entry(tab2, width=25, font=("Calibri 11"))
e_keyfile.grid(row=1, column=1, columnspan=3, padx=10, pady=10)

# Decrypt

########## Decrypting textfile function ##########
def decrypt():
    textfile_decrypt = open((e_textfile2.get()), "r").read()
    keyfile_decrypt = open((e_keyfile2.get()), "r").read()
    keyfile_decrypt = keyfile_decrypt.replace("\n", "")
    keyfile_decrypt = keyfile_decrypt.replace(" ", "")
    textfile_decrypt = textfile_decrypt.replace("\n", "")
    textfile_decrypt = textfile_decrypt.replace(" ", "")
    charset = {1: 'a', 2: 'b', 3: 'c', 4: 'd', 5: 'e', 6: 'f', 7: 'g', 8: 'h', 9: 'i', 10: 'j', 11: 'k', 12: 'l', 13: 'm', 14: 'n', 15: 'o', 16: 'p', 17: 'q', 18: 'r', 19: 's', 20: 't', 21: 'u', 22: 'v', 23: 'w', 24: 'x', 25: 'y', 26: 'z', 27: 'A', 28: 'B', 29: 'C', 30: 'D', 31: 'E', 32: 'F', 33: 'G', 34: 'H', 35: 'I', 36: 'J', 37: 'K', 38: 'L', 39: 'M', 40: 'N', 41: 'O', 42: 'P', 43: 'Q', 44: 'R', 45: 'S', 46: 'T', 47: 'U', 48: 'V', 49: 'W', 50: 'X', 51: 'Y', 52: 'Z', 53: '0', 54: '1', 55: '2', 56: '3', 57: '4', 58: '5', 59: '6', 60: '7', 61: '8', 62: '9', 63: ' ', 64: '!', 65: '"', 66: '#', 67: '$', 68: '%', 88: '&', 70: "'", 71: '(', 72: ')', 73: '*', 74: '+', 75: ',', 76: '-', 77: '.', 78: '/', 79: ':', 80: ';', 81: '<', 82: '=', 83: '>', 84: '?', 85: '@', 86: '[', 87: '\\', 89: ']', 90: '^', 91: '_', 92: '`', 93: '{', 94: '|', 95: '}', 96: '~', 97: '\n'}
    output_text = ""
    output_text_pre = []
    i = 0
    iterations = len(textfile_decrypt)
    for x in range(int(iterations / 2)):
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
    for x in output_text_pre:
        if x in charset:
            output_text = output_text + charset[x]
    f = open("decrypted_file.txt", "x")
    f.write(output_text)
    f.close()
    window_alert2("The decrypted file has been created.")

##################################################

def open_textfile2():
    filename_textfile2 =  filedialog.askopenfilename(initialdir = "/",title = "Select file")
    e_textfile2.delete(0, END)
    e_textfile2.insert(0, filename_textfile2)

def open_keyfile2():
    filename_keyfile2 =  filedialog.askopenfilename(initialdir = "/",title = "Select file")
    e_keyfile2.delete(0, END)
    e_keyfile2.insert(0, filename_keyfile2)

button_textfile2 = Button(tab3, text="Select Textfile", padx=0, pady=0, command=open_textfile2)
button_textfile2.grid(row=0, column=0)

button_keyfile2 = Button(tab3, text="Select Keyfile", padx=0, pady=0, command=open_keyfile2)
button_keyfile2.grid(row=1, column=0)

button_decrypt = Button(tab3, text="Decrypt", padx=10, pady=7, command=decrypt)
button_decrypt.grid(row=2, column=1)

e_textfile2 = Entry(tab3, width=25, font=("Calibri 11"))
e_textfile2.grid(row=0, column=1, columnspan=3, padx=10, pady=10)

e_keyfile2 = Entry(tab3, width=25, font=("Calibri 11"))
e_keyfile2.grid(row=1, column=1, columnspan=3, padx=10, pady=10)

# Checksum

########## Checksum function ##########
def checksum():
    file = open((e_file.get()), "r").read()
    checksum_file = open((e_checksum.get()), "r").read()
    checksum = hashlib.sha512((file).encode('utf-8')).hexdigest()
    if checksum == checksum_file :
        window_alert2("- SUCCESS -   The checksum matches")
    else:
        window_alert2("- FAILED -   The checksum does NOT match")
#######################################

def open_textfile3():
    filename_textfile3 =  filedialog.askopenfilename(initialdir = "/",title = "Select file")
    e_file.delete(0, END)
    e_file.insert(0, filename_textfile3)

def open_keyfile3():
    filename_keyfile3 =  filedialog.askopenfilename(initialdir = "/",title = "Select file")
    e_checksum.delete(0, END)
    e_checksum.insert(0, filename_keyfile3)

button_textfile3 = Button(tab4, text="Select File", padx=0, pady=0, command=open_textfile3)
button_textfile3.grid(row=0, column=0)

button_keyfile3 = Button(tab4, text="Select Checksum", padx=0, pady=0, command=open_keyfile3)
button_keyfile3.grid(row=1, column=0)

button_checksum = Button(tab4, text="Check", padx=10, pady=7, command=checksum)
button_checksum.grid(row=2, column=1)

e_file = Entry(tab4, width=25, font=("Calibri 11"))
e_file.grid(row=0, column=1, columnspan=3, padx=10, pady=10)

e_checksum = Entry(tab4, width=25, font=("Calibri 11"))
e_checksum.grid(row=1, column=1, columnspan=3, padx=10, pady=10)


# MAIN
tab_parent.grid(row=0, column=0)
form.resizable(False, False)
form.mainloop()