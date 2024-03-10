import os
import hashlib
import numpy as np
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk

form = tk.Tk()
form.title("Bitwise XOR Cipher")

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
def keygen():
    key_list = []
    for x in range(int(e_iterations.get())):
        key_list.append(ord(os.urandom(1)))
    f = open(e_key.get() + ".key", 'wb')
    f.write(bytes(key_list))
    f.close()

    f_to_checksum = open(e_key.get() + ".key", "rb").read()
    checksum = hashlib.sha512(f_to_checksum).hexdigest()
    f2 = open((e_key.get() + ".key" + ".sha512"), "x")
    f2.write(checksum)
    f2.close()
    window_alert2("Key file has been created.\nChecksum of key has been created.")
#############################################

label_iterations = Label(tab1, text="Lenght of key:")
label_iterations.grid(row=0, column=0)

label_key = Label(tab1, text="Name of key:")
label_key.grid(row=1, column=0)

button_keygen = Button(tab1, text="Generate key", padx=10, pady=7, command=keygen)
button_keygen.grid(row=2, column=1)

e_iterations = Entry(tab1, width=25, font=("Calibri 11"))
e_iterations.grid(row=0, column=1, columnspan=3, padx=10, pady=10)

e_key = Entry(tab1, width=25, font=("Calibri 11"))
e_key.grid(row=1, column=1, columnspan=3, padx=10, pady=10)


# TAB TWO

######### Encrypting file function and generating checksum ##########
def encrypt():
    file = open(e_textfile.get(), "rb")
    byte_list = file.read()
    byte_list2 = []
    for x in byte_list:
        byte_list2.append(x)

    file2 = open(e_keyfile.get(), "rb")
    key_list = file2.read()
    key_list2 = []
    for x in key_list:
        key_list2.append(x)
    
    key_list2 = key_list2[:len(byte_list2)]

    result_list = np.bitwise_xor(byte_list2, key_list2).tolist()
    
    f = open(e_textfile.get() + ".enc", 'wb')
    f.write(bytes(result_list))
    f.close()

    f_to_checksum = open(e_textfile.get() + ".enc", "rb").read()

    checksum =  hashlib.sha512(f_to_checksum).hexdigest()
    f2 = open((e_textfile.get() + ".enc" + ".sha512"), "x")
    f2.write(checksum)
    f2.close()

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


button_textfile = Button(tab2, text="Select File", padx=0, pady=0, command=open_textfile)
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
    file = open(e_textfile2.get(), "rb")
    byte_list = file.read()
    byte_list2 = []
    for x in byte_list:
        byte_list2.append(x)

    file2 = open(e_keyfile2.get(), "rb")
    key_list = file2.read()
    key_list2 = []
    for x in key_list:
        key_list2.append(x)
    
    key_list2 = key_list2[:len(byte_list2)]

    result_list = np.bitwise_xor(byte_list2, key_list2).tolist()
    
    f = open(e_textfile2.get().replace(".enc", ".dec"), 'wb')
    f.write(bytes(result_list))
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

button_textfile2 = Button(tab3, text="Select File", padx=0, pady=0, command=open_textfile2)
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
    file = open((e_file.get()), "rb").read()
    checksum_file = open((e_checksum.get()), "r").read()
    checksum = hashlib.sha512(file).hexdigest()
    if checksum == checksum_file :
        window_alert2("\n - SUCCESS -   The checksum matches\n")
    else:
        window_alert2("\n - FAILED -   The checksum does NOT match\n")
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