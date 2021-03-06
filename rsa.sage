import os

q=random_prime(2^512)
p=random_prime(2^512)
n=p*q
phi=(p-1)*(q-1)
e=3

# public key generation
while gcd(e, phi) != 1:
   e = ZZ.random_element(phi)
# private key generation
bezout=xgcd(e,phi)
d = Integer(mod(bezout[1], phi))

def encrpytion_decryption():
      temp_plain_text=""
      temp_decrypted_text=""
      temp_plain_text1=""
      plain_text=read_file(file_name="plain")
      for i in range(0, len(plain_text), 100):
         text_block = plain_text[i:i + 100]
         if len(text_block) != 100:
            # buffer the block up to length reach 100
            while len(text_block) != 100:
               text_block += "0"
         else:
            for i in range(0, len(text_block)):
               temp = str(ord(text_block[i]))
               if len(temp) != 3:
                  temp = "0" + temp
               temp_plain_text += temp

            # using repeated squaring to find encrpyted message
            cipher_text = pow(int(temp_plain_text), e, n)
            temp_plain_text = ""
            file = open(os.getcwd() + "/cipher.rsa", mode="a")
            file.write(str(cipher_text))
            # decryption using private key
            decrypted_text = str(pow(cipher_text, d, n))
            if len(decrypted_text) != 300:
               decrypted_text = "0" + decrypted_text

            for i in range(0, len(decrypted_text), 3):
               temp = chr(int(decrypted_text[i:i + 3]))
               temp_decrypted_text += str(temp)

            decrypted_text = temp_decrypted_text

            text_block = decrypted_text
            decrypted_text = ""

            temp_plain_text1 += text_block
      write_file(file_name="decrypted",data=temp_plain_text1)


def read_file(file_name):
      file = open(os.getcwd() + "/"+file_name,mode='r')
      plain_text = file.read()
      return plain_text

def write_file(file_name,data):
      file=open(os.getcwd()+"/"+file_name,mode="w+")
      file.write(data)


if __name__ == '__main__': 
    try:
        print("Encryption started")
        encrpytion_decryption()
        print("Decrpytion ended")
    except Exception as e:
        print("Error occured while executing reason is {}".format(e))


