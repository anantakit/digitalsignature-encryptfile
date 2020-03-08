from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
from Crypto.Cipher import AES
import os
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_aesKey():
    # 32 bytes * 8 = 256 bits (1 byte = 8 bits)
    key = get_random_bytes(32)
    file_out = open("aesKey.bin", "wb") 
    file_out.write(key)
    file_out.close()
    return key

def get_aesKey():
    try:
        file_in = open("aesKey.bin", "rb") 
        key_from_file = file_in.read() 
        file_in.close()
        return key_from_file
    except:
        return generate_aesKey()

def generate_rsaKey():
    private_key = RSA.generate(bits=2048)
    public_key = private_key.publickey()
    
    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()

    with open('private_pem.pem', 'w') as pr:
        pr.write(private_pem)

    with open('public_pem.pem', 'w') as pu:
        pu.write(public_pem)

    return private_key, public_key

def get_rsaKey():
    try:
        private_key = RSA.import_key(open('private_pem.pem', 'r').read())
        public_key = RSA.import_key(open('public_pem.pem', 'r').read())
        return private_key,public_key
    except:
        return generate_rsaKey()

aesKey = get_aesKey()

private_key,public_key = get_rsaKey()

def sign(message):
    hash = SHA256.new(message)
    signer = PKCS115_SigScheme(private_key)
    signature = signer.sign(hash)
    print("hash: ", hash.hexdigest())
    print("Signature:", binascii.hexlify(signature))

    fo = open(filename + ".sig", 'wb')
    fo.write(signature)
    fo.close()

def verify(message, signature):
    hash = SHA256.new(message)
    signer = PKCS115_SigScheme(public_key)
    print("hash: ", hash.hexdigest())
    print("Signature:", binascii.hexlify(signature))
    try:
        signer.verify(hash, signature)
        print("Signature is valid.")
    except:
        print("Signature is invalid.")

def encrypt(message,iv=Random.new().read(AES.block_size)):
    message = pad(message, AES.block_size)
    cipher = AES.new(aesKey, AES.MODE_CBC,iv)
    return iv, cipher.encrypt(message)

def encrypt_file(file_name):
    fo = open(file_name, 'rb')
    plaintext = fo.read()
    fo.close()

    iv,cipher = encrypt(plaintext)

    fo = open(file_name + ".enc", 'wb')
    fo.write(iv + cipher)
    fo.close()
    os.remove(file_name)

def decrypt(ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext

def decrypt_file(file_name):
    fo = open(file_name, 'rb')
    ciphertext = fo.read()
    fo.close()

    dec = decrypt(ciphertext)

    fo = open(file_name[:-4], 'wb')
    fo.write(dec)
    fo.close()
    os.remove(file_name)

if __name__ == "__main__":

    while True:
        choice = int(input(
            "1. Press '1' to encrypt file.(if file .txt sign digitalsignature)\n2. Press '2' to decrypt file.(if file .txt then verify digitalsignature)\n3. Press '3' to exit.\n"))

        if choice == 1 or choice == 2:
            filename = str(input("Enter name of file: "))

            if filename.endswith(".txt") or filename[:-4].endswith(".txt"):
                if choice == 1:
                    fo = open(filename, "rb")
                    message = fo.read()
                    fo.close()

                    print('message: ', message)
                    sign(message)
                
                else:
                    fo = open(filename, "rb")
                    signature = fo.read()
                    fo.close()

                    fo = open(filename[:-4], 'rb')
                    message = fo.read()
                    
                    print('message: ', message)
                    verify(message,signature)

            else:
                if choice == 1:
                    encrypt_file(filename)
                else:
                    decrypt_file(filename)


        elif choice == 3:
            exit()
        else:
            print("Please select a valid option!")