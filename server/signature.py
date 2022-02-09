import Crypto.Signature.PKCS1_v1_5 as sign_PKCS1_v1_5
from Crypto import Hash
from Crypto.PublicKey import RSA
from pyDes import des, PAD_PKCS5, ECB


def to_sign_with_private_key(plain_text, my_private_key):  # 私钥签名
    signer_pri_obj = sign_PKCS1_v1_5.new(RSA.importKey(my_private_key))
    rand_hash = Hash.SHA256.new()
    rand_hash.update(plain_text.encode())
    signature = signer_pri_obj.sign(rand_hash)
    return to_str(signature)

def to_bytes(param):  # str---->bytes
    if isinstance(param, str):
        value = param.encode('ISO-8859-1')
    elif isinstance(param, bytes):
        value = param
    else:
        value = 'type_error'
    return value

def to_str(param):  # bytes---->str
    if isinstance(param, bytes):
        value = param.decode('ISO-8859-1')
    elif isinstance(param, str):
        value = param
    else:
        value = 'type_error'
    return value