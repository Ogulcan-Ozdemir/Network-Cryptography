import os
from sage.crypto.util import random_prime
import hashlib,re,sys

def public_key():

    global p, q, g, x, y, k, h
    q=1
    while q<2^15:
        q=random_prime(2^16)
    print "q ", q
    p=1
    while not is_prime(p):
        p=(2^47+randint(1,2^45)*2)*q+1
    print "p ", p
    F=GF(p)
    h=randint(2,p-1)
    print "h ", h
    g=(F(h)^((p-1)/q)).lift()
    print "g ",g
    x=ZZ.random_element(0,q-1) # user's private key
    print "x ",x
    y=g.powermod(x,p) #g^x mod p # user's public key
    print "y ",y
    k=ZZ.random_element(0,q-1) #user's per message secret numbr
    print "k ",k


def sign():
    file = open(os.getcwd() + "/plain", mode="r")
    m = file.read()

    k = randint(2, q - 1)
    F = GF(p)
    r = F(g) ^ k
    r = r.lift() % q #(g^k mod p)mod q

    M = hashlib.sha1(m)
    digest_m = " "
    for i in M.hexdigest():
        digest_m += str(ord(i))
    k1 = xgcd(k, q)[1] % q #k1 equal of k^-1
    s = k1 * (int(digest_m) + int(x * r)) % q #(k^-1(H(m)+x*r))mod q

    print "s ",s
    print "r ",r
    file=open(os.getcwd()+"/signed",mode="w+")
    m+="s,r-"+str(s)+"-"+str(r)
    file.write(m)
    print "signed message write in current directory as signed.txt"


def verify():
    file=open(os.getcwd()+"/signed",mode="r")
    m=file.read()
    regex=re.compile('-\d*')
    s=Integer( regex.findall(m)[0].split('-')[1])
    r=Integer(regex.findall(m)[1].split('-')[1])
    m=m.strip("s,r-"+str(s)+"-"+str(r))
    print "Text  from signed\n ",m
    print "s from signed ",s
    print "r from signed",r

    w=s.powermod(-1,q) #s^-1 mod q
    print "w ",w
    M = hashlib.sha1(m)
    digest_m = ""
    for i in M.hexdigest():
        digest_m += str(ord(i))
    u1=(int(digest_m)*w)%q #(H(m)*w)mod q
    print "u1 ", u1
    u2=(r*int(w))%q
    print "u2 ",u2
    v=float((((g ^ u1)*(y ^ u2)) % p) % q)
    print "Verifying ", v==r

def main() : 
    i=""#just for loop work properly
    while i!="exit":
        print "--------------------------------"
        print "DSA"
        print "1-generate public key components"
        print "2-Sign document"
        print "3-Verify document"
        print "4-exit terminate program"
        i=raw_input()
        print "--------------------------------"

        if i=="1":
            public_key()
        elif i=="2":
            sign()
        elif i=="3":
            verify()
        elif i=="4":
            i="exit"

 if __name__ == '__main__': 
    try:
        main()
    except Exception as e:
        print("Error occured while executing reason is {}".format(e))
           