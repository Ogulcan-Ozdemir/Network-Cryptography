import tkinter.filedialog
import os
from itertools import permutations
from collections import deque
import random
import binascii
from base64 import b64encode

def simple_des():
    print("Please choose file to encryt")
    # find file path and read
    file = tkinter.filedialog.askopenfilename()
    f = open(file, 'r',encoding="utf-8")
    encrypted_file_name =  str(os.path.basename(f.name)).split(".")[0]
    plain_text = f.read()
    print("Text read done key generation starting")
    # key generation
    key = os.urandom(2)
    key = b64encode(key).decode('utf-8')
    key = ' '.join(format(ord(x), 'b') for x in key)
    key = key[:18]
    key = key.replace(' ', '')
    print("key generation done")
    # one's complement of key
    key = list(key)
    for i in range(0, len(key)):
        if key[i] == "0":
            key[i] = "1"
        elif key[i] == "1":
            key[i] = "0"
    key = ''.join(key)
    # key spliting two partions
    key1 = key[:8]
    key2 = key[8:]
    # keys initial permutation
    initialpermkey1 = [7, 0, 2, 3, 5, 1, 4, 6]
    initialpermkey2 = [6, 4, 2, 5, 3, 2, 0, 7]
    key1 = list(key1)
    key2 = list(key2)
    for i, val in enumerate(initialpermkey1):
        key1[i] = key1[val]
    ciphertext = ""
    for i, val in enumerate(initialpermkey2):
        key2[i] = key2[val]
    plain_text = plain_text.replace(' ', '')
    cnt = 0
    print("Encryption starting")
    while cnt <= len(plain_text):
        temp = plain_text[cnt:cnt + 10]
        if 10 > len(temp):
            a = 10 - len(temp)
            for i in range(0, a):
                temp += "1"
        # random permutation of plain text
        temp = random.sample(temp, len(temp))
        temp = "".join(temp)
        # initial permutation of plain text
        initialperm = [9, 7, 5, 3, 1, 8, 6, 4, 2, 0]
        tempperm = [None] * len(temp)
        for i, val in enumerate(initialperm):
            tempperm[i] = temp[val]
        temp = tempperm
        # shift right rotate of plain text
        temp = ''.join(temp)
        temp = deque(temp)
        temp.rotate(-4)
        temp = ''.join(temp)
        # text block spliting two partions
        righttemp = ""
        lefttemp = ""
        for i in range(0, len(temp)):
            if i % 2 == 0:
                righttemp += temp[i]
            else:
                lefttemp += temp[i]
        # characters convert binary
        lefttemp = bin(int.from_bytes(lefttemp.encode('utf-8', 'surrogatepass'), 'big'))[2:]
        lefttemp = lefttemp.zfill(8 * ((len(lefttemp) + 7) // 8))
        righttemp = bin(int.from_bytes(righttemp.encode('utf-8', 'surrogatepass'), 'big'))[2:]
        righttemp = righttemp.zfill(8 * ((len(righttemp) + 7) // 8))
        # bytes xor'd keys of
        iterate = [0, 8, 16, 24, 31]
        lefttemp2 = []
        rightemp2 = []
        rigttemp = list(righttemp)
        for i, val in enumerate(iterate):
            lefttemp1 = lefttemp[val:val + 8]
            rightemp1 = list(righttemp[val:val + 8])
            lefttemp1 = list(lefttemp1)
            rightemp1 = list(rightemp1)

            for i, val in enumerate(lefttemp1):
                if lefttemp1[i] == key2[i]:
                    lefttemp1[i] = "0"
                elif lefttemp[i] != key2[i]:
                    lefttemp1[i] = "1"
            for i, val in enumerate(rightemp1):
                if rightemp1[i] == key1[i]:
                    rightemp1[i] = "0"
                elif rightemp1[i] != key1[i]:
                    rightemp1[i] = "1"
            lefttemp2.extend(lefttemp1)
            rightemp2.extend(rightemp1)
        lefttemp2 = "".join(lefttemp2)
        rightemp2 = "".join(rightemp2)
        lefttemp = lefttemp2
        righttemp = rightemp2
        # first key shift rotate
        key1 = ''.join(key1)
        key1 = deque(key1)
        key1.rotate(-4)
        key1 = ''.join(key1)
        # second key shift rotate
        key2 = ''.join(key2)
        key2 = deque(key2)
        key2.rotate(-4)
        key2 = ''.join(key2)
        # change place of blocks
        temp2 = lefttemp
        lefttemp = righttemp
        righttemp = temp2
        lefttemp2 = []
        righttemp2 = []
        # second xor
        iterate1 = [0, 8, 16, 24, 31]
        for i, val in enumerate(iterate1):
            lefttemp1 = list(lefttemp[val:val + 8])
            rightemp1 = list(righttemp[val:val + 8])
            lefttemp2 = list(lefttemp2)
            righttemp2 = list(righttemp2)
            for i, val in enumerate(lefttemp1):
                if lefttemp1[i] == key2[i]:
                    lefttemp1[i] = "0"
                elif lefttemp[i] != key2[i]:
                    lefttemp1[i] = "1"
            for i, val in enumerate(rightemp1):
                if rightemp1[i] == key1[i]:
                    rightemp1[i] = "0"
                elif rightemp1[i] != key[i]:
                    rightemp1[i] = "1"
            lefttemp2.extend(lefttemp1)
            righttemp2.extend(rightemp1)
        lefttemp2 = "".join(lefttemp2)
        righttemp2 = "".join(righttemp2)
        lefttemp = lefttemp2
        righttemp = righttemp2
        # concatante two parts
        temp = lefttemp + righttemp
        temp = int(temp)
        temp = temp.to_bytes((temp.bit_length() + 7) // 8, 'big').decode('latin-1', 'surrogateescape') or '\0'
        # reverse initial perm
        reverseinitialperm = [9, 4, 8, 3, 7, 2, 6, 1, 5, 0]
        tempperm = [None] * 10
        for i, val in enumerate(reverseinitialperm):
            tempperm[i] = temp[val]
        temp = tempperm
        temp = ''.join(str(v) for v in temp)
        cnt += 10
        ciphertext += temp
    # writing file
    encrypted_file_name = os.getcwd()+"\\"+encrypted_file_name+"_encoded.txt"
    f = open(encrypted_file_name, 'w+',encoding="utf-8")
    f.write(ciphertext)
    print("Encryption done encrypted text write into {} ".format(encrypted_file_name))


if __name__ == '__main__': 
    try:
        simple_des()
    except Exception as e:
        print("Error occured while executing simple_des reason is {}".format(e))