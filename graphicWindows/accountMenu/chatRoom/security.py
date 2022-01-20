
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

aliases=[]
pub_keys=[]

def configure_keys(private_key,secret,alias):
    global pub_key
    global priv_key

    encoded_key = open(private_key, "rb").read()
    priv_key = RSA.import_key(encoded_key, passphrase=secret)
    pub_key = priv_key.publickey().export_key()

    return pub_key

def add_user(name,pub_key):
    aliases.append(name)
    pub_keys.append(pub_key.encode("utf-8"))
    print(aliases)
    print(pub_keys)
    return name

def remove_user(name):
    i = aliases.index(name)
    alias = aliases[i]
    aliases.remove(alias)
    key = pub_keys[index]
    pub_keys.remove(key)

    return alias

def get_pub_key():
    return pub_key

def encrypt(message_data):

    if(len(aliases) != 0):

        recipient_key = RSA.import_key(pub_keys[0])
        # recipient_key = RSA.import_key(pub_key)
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message_data.encode("utf-8"))

        encrypted_message = b''.join([enc_session_key,cipher_aes.nonce,tag,ciphertext])

        return encrypted_message
    else: 
        return "NO_USER"

def decrypt(encrypted_message):



    enc_session_key = encrypted_message[:priv_key.size_in_bytes()]
    nonce = encrypted_message[priv_key.size_in_bytes():priv_key.size_in_bytes()+16]
    tag = encrypted_message[priv_key.size_in_bytes()+16:priv_key.size_in_bytes()+32]
    ciphertext = encrypted_message[priv_key.size_in_bytes()+32:]

    # Decrypt the session key with the private RSA key
    cipher = PKCS1_OAEP.new(priv_key)
    session_key = cipher.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    

    return data.decode("utf-8")


def find_length(message):
    n = ["0","1","2","3","4","5","6","7","8","9"]

    digits=[]
    test = True
    i=0
    while test:
        x = message[12+i:13+i]
        num = str(x.decode("utf-8"))
        if num in n:
            if i == 0 and num == "0":
                return 0
            digits.append(num)
            i += 1
        else:
            test = False
    size = 0
    for i in range(len(digits),-1,-1):
        if i != 0:
            size += int(digits[i-1]) * pow(10,3-i)

    name = message[15+len(digits):len(message)-3-size]

    return size,name