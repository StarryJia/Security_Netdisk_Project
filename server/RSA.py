import socket    # 调用模块
import json
import threading
import hashlib
import time 
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64
import os
from Crypto import Random
import base64

def rsa_long_encrypt(pub_key_str, msg):
    msg = msg.encode('utf-8')
    length = len(msg)
    default_length = 117
    #公钥加密
    pubobj = Cipher_pkcs1_v1_5.new(RSA.importKey(pub_key_str))
    #长度不用分段
    if length < default_length:
        return base64.b64encode(pubobj.encrypt(msg))
    #需要分段
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(pubobj.encrypt(msg[offset:offset+default_length]))
        else:
            res.append(pubobj.encrypt(msg[offset:]))
        offset += default_length
    byte_data = b''.join(res)
    return base64.b64encode(byte_data)



def rsa_long_decrypt(priv_key_str, msg):
    msg = base64.b64decode(msg)
    length = len(msg)
    default_length = 128
    #私钥解密
    priobj = Cipher_pkcs1_v1_5.new(RSA.importKey(priv_key_str))
    #长度不用分段
    if length < default_length:
        return b''.join(priobj.decrypt(msg, b'xyz'))
    #需要分段
    offset = 0
    res = []
    while length - offset > 0:
        if length - offset > default_length:
            res.append(priobj.decrypt(msg[offset:offset+default_length], b'xyz'))
        else:
            res.append(priobj.decrypt(msg[offset:], b'xyz'))
        offset += default_length

    return b''.join(res)