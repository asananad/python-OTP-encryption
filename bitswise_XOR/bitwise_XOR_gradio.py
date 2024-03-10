import gradio as gr
import numpy as np
import os, sys, hashlib, tempfile


######### keygen #############
def keygen(filepath, byte_amount):
    byte_amount = int(byte_amount)
    if byte_amount == 0: # file length as input
        print(filepath.name)
        key_bytelist = []
        file_inputted = open(filepath, "rb")
        file_buffer = file_inputted.read()
        file_bytelist = []
        for x in file_buffer:
            file_bytelist.append(x)
        for x in range(len(file_bytelist)):
            key_bytelist.append(ord(os.urandom(1)))
    if byte_amount > 0: # provided length as input
        key_bytelist = []
        for x in range(byte_amount):
            key_bytelist.append(ord(os.urandom(1)))
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(bytes(key_bytelist))
        f.close()
    return f.name
##############################

######### encrypt ############
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

    print("\n The encrypted file has been created.\n")

    f_to_checksum = open(sys.argv[2] + ".enc", "rb").read()

    checksum = hashlib.sha512(f_to_checksum).hexdigest()
    f2 = open((sys.argv[2] + ".enc" + ".sha512"), "x")
    f2.write(checksum)
    f2.close()
    print("\n The sha512 checksum file has been created.\n")
##############################


########## decrypt ###########
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
##############################

######### check checksum ###########
def checksum_check(file):
    file_bytedata = file.read()
    checksum_file = open((sys.argv[3]), "r").read()
    checksum = hashlib.sha512(file).hexdigest()
    print("\n " + checksum_file + "\n " + checksum + "\n")
    if checksum == checksum_file :
        print("\n - SUCCESS -   The checksum matches\n")
    else:
        print("\n - FAILED -   The checksum does NOT match\n")
##############################

########## gen checksum ##########

def checksum_gen(file):
    f_to_checksum = file.read()
    checksum = hashlib.sha512(f_to_checksum).hexdigest()
    return checksum

################################


######### gradio ###############
with gr.Blocks() as demo:
    with gr.Row():
        gr.Text(label="", value="Select a file as input in order to create a random key of equal length to the length of the file in bytes, or manually choose the desired length of the key below.")
    with gr.Row():
        fileinput = gr.File(label="Input file")
        fileoutput = gr.File(label="Output file")
    with gr.Row():
        with gr.Accordion("Manually select length of key", open=False):
            numberinput = gr.Number(precision=0, label="Byte length (It will be rounded down to integer)")
    with gr.Row():
        btn = gr.Button(value="Submit")
        btn.click(keygen, inputs=[fileinput, numberinput], outputs=fileoutput)
################################

########### main ###############
#if __name__ == "__main__":
demo.launch()
################################