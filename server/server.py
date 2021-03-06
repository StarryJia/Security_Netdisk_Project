# coding=utf-8
"""
Auther : StarryJia
Version : 1.0.0
Time : 2021.9.7
"""

from pymysql import DATE
import socket        # 调用模块
import json
import threading
import time
import RSA
import send_mail
import signature
import sqlserver
import os
import string
import random
from pyDes import des, PAD_PKCS5, ECB

#下面的是服务器的私钥
privateKEY = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCk0cz26CD0+rXElDGFO+Ugd3rAIfdaL8ut/lQ9e9MZhT0oLHGM\nFnlXDmEG8nY94IqMhlxvS9Fyde1oTDpguw//xshB4bt2z/ticTvfLe8KjyhmIQHo\nFL/wzuoftVmWfiOM/HrHJwHH5nYit9eZfAsvWgFRA3XYDT5jOTtFza1FtQIDAQAB\nAoGAOSyGG0he1lx53V1C6GLkkqSfsjKWKXTXBN5qvoFLs1ii5GK2aNAK+4YDZnOJ\nTOGtbh3Vxs3YNApwdnOq9I8vdw4sTSksWhXiZJGDlC60bGl7Iut0Agy/nUuIblWn\nTO9RBorrHVG8FkzBtr6FBiHSYpZAsOTOOyft5UYr/AtBJ6kCQQDMX80MxbzHzf67\nMwvkaRrsQE5OGd3M5DemUqo1VbgLInUOKRbjJxW7c7FxnkhEi707xfEH1whulAh5\nwBqXvS33AkEAznQhQtjRUPu/VDM8hrTys0jiny/dxSAwCSeqIaejMEvpMyXtSc59\nMDY5gkS0qVZcvPhtugDHfN8hhT/SmQpuswJALQ/KdFB9CUkAK2Jb8ubByul62nmV\nkAGZy5BaexwFUl8slAy3QSpy/jvKGhUeNg7hkHZaaLIe59K387BJrL9HjQJAJ74j\nSQMECFruEf9q/2OF9Q1q0socHv57QMfp8GCdAYcbdUUv0K13W/iUSYeAX7jIUXhh\nZxUPUfKCOWx31g40EQJBAKLxWu4KhAe+Ti544eAI4kSJKGZ4aKAQeX/4SIjlEND0\npfWVkQb3osDhVbnZyTb6bBVHilPISiu+gXVtMPNBYng=\n-----END RSA PRIVATE KEY-----'

'''全局变量定义：
1.captcha_dic = {ID:[captcha,ID,PASSWORD,MAIL]} 记录给每个用户发送的验证码,以及用户的注册信息，用于校验并注册
2.session_key = {ID：session_key} 记录每个用户的会话密钥，每次登陆的时候刷新
3.CD_dic =  {ID：time} 记录每个用户还需要等待的时间
4.captcha_dic2 = {ID：captcha} 记录用户重置密码的时候的验证码，用于后面校验
'''
captcha_dic = {} 
session_key = {}
CD_dic =  {} 
captcha_dic2 = {}


def register(ID,PASSWORD,MAIL) : #注册操作，需要注册人的帐号，密码以及邮箱
    sqlserver.register(ID,PASSWORD,MAIL) #进行注册
    return 0 #注册成功

def login(ID,PASSWORD) : #登陆操作，需要登陆人的帐号和密码
    if sqlserver.find_id(ID) == 1 :
        status = sqlserver.login(ID,PASSWORD) #检查登陆的信息是否正确
        if status == 0 : #登陆审核通过
            return 0 #登陆成功
        return 5 #账号密码错误
    return 6 #账户不存在

def check_timestamp(timestamp) : #检查时间戳，如果正常则返回0，否则返回1
    tictoc =  time.time()
    if tictoc - timestamp > 60 :#如果大于一分钟则返回1
        return 1
    else :
        return 0

def get_captcha() : # 获得验证码，该函数用于生成六位随机验证码
    captcha = ''
    words = ''.join((string.ascii_letters,string.digits))##生成大小写字母和数这串
    for i in range(6):
        captcha += random.choice(words)
    return captcha

def sleep_handle() : # 用户登陆过于频繁，用户进入冷却，该函数用于调整用户的冷却时间
    while True :
        for value in CD_dic.values() :
            if value[1] > 0 :
                value[1] = value[1] - 30
        time.sleep(30)


def mkdir(path): # 创建文件夹，为个人空间或者组空间创建文件夹
	folder = os.path.exists(path)
	if not folder:                   #判断是否存在文件夹如果不存在则创建为文件夹
		os.makedirs(path)            #makedirs 创建文件时如果路径不存在会创建这个路径
		print("---  new folder...  ---")
		print("---  OK  ---")
	else:
		print("---  There is this folder!  ---")


def client_handle() : #最主要的线程函数，调用status_handle用于接收并处理用户的各种请求
    while True :
        conn, addr = sk.accept()    # 等待客户端连接
        data = b''
        while True :
            receive = conn.recv(4096)    # 接收的信息
            if receive == 'EOF'.encode() :
                break
            data = data + receive
        data = str(data,encoding='utf-8')#将信息解码
        data = json.loads(data) #转换成python的数据结构
        print("接收到的消息：",data)
        result = status_handle(data,conn,addr)
        print("发送回去的消息:",result)
        message = json.dumps(result)
        message = bytes(message.encode())
        conn.sendto(message,addr)# bytes编码后发信息
        conn.close()


def status_handle(Data,conn,addr) : # 用户请求处理函数，对用户的各种请求进行分析并处理
    status = Data[0]
    if status == 1 : #收到用户注册请求，进入第一阶段，状态码为1，数据包的结构为 [时间戳，用户ID的哈希值，用户PASSWORD的哈希值，用户的邮箱]
        data = Data[1]
        data = RSA.rsa_long_decrypt(privateKEY,data)
        data = json.loads(data) #转换成python的数据结构
        timestamp = data[0]
        if check_timestamp(timestamp) == 1 :
            msg = ['1',signature.to_sign_with_private_key('1',privateKEY)]
            return msg #返回
        ID = data[1]
        PASSWORD = data[2]
        MAIL = data[3]
        if sqlserver.find_id(ID) == 1 : #ID已经被注册返回状态码4
            msg = ['4',signature.to_sign_with_private_key('4',privateKEY)]
            return msg
        captcha = get_captcha()
        captcha_dic[ID] = [captcha,ID,PASSWORD,MAIL]
        #print('验证码：',captcha)
        send_mail.sendcaptcha(MAIL,captcha)
        msg = ['2',signature.to_sign_with_private_key('2',privateKEY)]
        return msg #返回2代表等待输入验证码
    
    if status == 2 : #注册请求第二阶段，需要验证邮箱
        data = Data[1]
        data = RSA.rsa_long_decrypt(privateKEY,data)
        data = json.loads(data) #转换成python的数据结构
        captcha = data[0]
        ID = data[1]
        register_list = captcha_dic[ID]
        PASSWORD = register_list[2]
        MAIL = register_list[3]
        if captcha == register_list[0] :
            register(ID,PASSWORD,MAIL)
            msg = ['0',signature.to_sign_with_private_key('0',privateKEY)]
            path = r'D:/Net disk' + r'/personal' + r'/%s' %ID
            mkdir(path)
            return msg #返回0代表验证码成功注册成功
        else :
            msg = ['3',signature.to_sign_with_private_key('3',privateKEY)]
            return msg #返回3代表验证码错误

    if status == 3 : #登录请求
        data = Data[1]
        data = RSA.rsa_long_decrypt(privateKEY,data)
        data = json.loads(data) #转换成python的数据结构
        timestamp = data[0]
        KEY = data[1]
        ID = data[2]
        PASSWORD = data[3]
        code = login(ID,PASSWORD)
        if ID in CD_dic.keys() :
            if CD_dic[ID][0] == 3 :
                CD_dic[ID] = [0,90]
                msg = ['300',signature.to_sign_with_private_key('300',privateKEY)]
                return msg
            if CD_dic[ID][1] != 0 :
                msg = ['300',signature.to_sign_with_private_key('300',privateKEY)]
                return msg #登陆太频繁，消息码300
        else :
            CD_dic[ID] = [0,0]
        if code == 0: #返回200，代表登陆成功
            CD_dic[ID] = [0,0]
            session_key[ID] = KEY
            msg = ['200',signature.to_sign_with_private_key('200',privateKEY)]
        if code == 5 : #返回5，账号密码错误
            msg = ['5',signature.to_sign_with_private_key('5',privateKEY)]
            CD_dic[ID][0] = CD_dic[ID][0] + 1
        if code == 6 : #返回6，帐号不存在
            msg = ['6',signature.to_sign_with_private_key('6',privateKEY)]
        return msg 

    if status == 4 : #收到重置密码的请求
        data = Data[1]
        data = RSA.rsa_long_decrypt(privateKEY,data)
        data = json.loads(data) #转换成python的数据结构
        ID = data[0]
        if sqlserver.find_id(ID) == 0 :
            msg = ['7',signature.to_sign_with_private_key('7',privateKEY)]
            return msg #要重置的ID不存在
        MAIL = sqlserver.mailaccess(ID)
        captcha = get_captcha()
        captcha_dic2[ID] = captcha
        #print('验证码',captcha)
        send_mail.sendcaptcha(MAIL,captcha)
        msg = ['8',signature.to_sign_with_private_key('8',privateKEY)]
        return msg #收到重置密码请求，等待邮箱验证码

    if status == 5 : #重置密码时，校验验证码,如果验证成功则修改密码
        data = Data[1]
        data = RSA.rsa_long_decrypt(privateKEY,data)
        data = json.loads(data) #转换成python的数据结构
        captcha = data[0]
        ID = data[1]
        PASSWORD = data[2]
        if captcha == captcha_dic2[ID] :
            msg = ['10',signature.to_sign_with_private_key('10',privateKEY)]
            sqlserver.passchange(ID,PASSWORD)
        else : 
            msg = ['11',signature.to_sign_with_private_key('11',privateKEY)]
        return msg #要重置密码前的邮箱验证操作，10代表通过了验证并修改了密码，11代表没有通过邮箱验证

    if status == 7 :#个人上传的申请[7,ID,[file_name,file_key],file_content]
        ID = Data[1]
        data = Data[2]
        file_content = Data[3]
        KEY = session_key[ID]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        data = json.loads(data) # data = [file_name,file_key]
        filelist = data
        file_name = filelist[0]
        file_key = filelist[1]
        filepath = r'D:/Net disk' + r'/personal' + r'/%s' %ID
        file = sqlserver.uploadfile(ID,file_name,filepath,file_key,0)
        print("filekey:",file_key)
        with open(file,"wb") as f:
            f.write(signature.to_bytes(file_content))
            f.close()
        file_dic= sqlserver.fileaccess(ID)
        file_dic = json.dumps(file_dic)
        msg = des_main.encrypt(file_dic)
        msg = signature.to_str(msg)
        return msg

    if status == 8 :#个人下载的请求[8,ID,file_id]
        ID = Data[1]
        KEY = session_key[ID]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = Data[2]
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        file_id = signature.to_str(data)
        filepath = sqlserver.downloadfile(ID,file_id)
        with open(filepath, 'rb') as f:
            for data in f :
                conn.sendto(data,addr)
        time.sleep(1)
        conn.sendto('EOF'.encode(),addr)
        msg = ['13',signature.to_sign_with_private_key('13',privateKEY)]
        return msg

    if status == 9 :#个人删除文件的请求,[9,ID,file_id]
        ID = Data[1]
        KEY = session_key[ID]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = Data[2]
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        file_id = signature.to_str(data)
        filepath = sqlserver.deletefile(ID,file_id)
        os.remove(filepath)
        file_dic= sqlserver.fileaccess(ID)
        file_dic = json.dumps(file_dic)
        msg = des_main.encrypt(file_dic)
        msg = signature.to_str(msg)
        return msg

    if status == 10 : #个人请求刷新文件列表，收到的数据包[10，ID]
        ID = Data[1]
        KEY = session_key[ID]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        file_dic= sqlserver.fileaccess(ID)
        file_dic = json.dumps(file_dic)
        msg = des_main.encrypt(file_dic)
        msg = signature.to_str(msg)
        return msg #将文件列表发回
    
    if status == 11 : #请求组的文件列表刷新，[11,ID,group_id]
        ID = Data[1]
        KEY = session_key[ID]
        group_id = Data[2]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        file_dic = sqlserver.g_fileaccess(group_id)
        file_dic = json.dumps(file_dic)
        msg = des_main.encrypt(file_dic)
        msg = signature.to_str(msg)
        return msg
    
    if status == 12 : #创建组,[12,ID,[group_id,group_password,group_name,group_cipher]]
        ID = Data[1]
        KEY = session_key[ID]
        data = Data[2]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        data = json.loads(data)
        group_id = data[0]
        group_password = data[1]
        group_name = data[2]
        group_cipher = data[3]
        code = sqlserver.creategroup(ID,group_id,group_password,group_name,group_cipher)
        if code == 1 :
            msg = ['15',signature.to_sign_with_private_key('15',privateKEY)] #创建失败返回15
            return msg
        msg = ['14',signature.to_sign_with_private_key('14',privateKEY)] #创建成功返回14
        path = r'D:/Net disk' + r'/group' + r'/%s' %group_id
        mkdir(path) #创建组文件夹
        return msg

    if status == 13 : #加入组,[13，ID,[group_id,group_password,group_cipher]]
        ID = Data[1]
        KEY = session_key[ID]
        data = Data[2]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = signature.to_bytes(data)
        data =  des_main.decrypt(data)
        data = json.loads(data)
        group_id = data[0]
        group_password = data[1]
        group_cipher = data[2]
        code = sqlserver.entergroup(ID,group_id,group_password,group_cipher)
        if code == 0 : #加入成功返回16
            msg = ['16',signature.to_sign_with_private_key('16',privateKEY)]
        if code == 1 : #加入码错误返回17
            msg = ['17',signature.to_sign_with_private_key('17',privateKEY)]
        if code == 2 : #组ID不存在返回18
            msg = ['18',signature.to_sign_with_private_key('18',privateKEY)]
        if code == 3 : #已经在组中
            msg = ['20',signature.to_sign_with_private_key('20',privateKEY)]
        return msg

    if status == 14 : #组上传文件[14,ID,[file_name,file_key,group_id],file_content]
        ID = Data[1]
        data = Data[2]
        file_content = Data[3]
        KEY = session_key[ID]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        data = json.loads(data) # data = [file_name,file_key,group_id]
        filelist = data
        file_name = filelist[0]
        file_key = filelist[1]
        group_id = filelist[2]
        filepath = r'D:/Net disk' + r'/group' + r'/%s' %group_id
        file = sqlserver.g_uploadfile(group_id,file_name,filepath,file_key,0)
        with open(file,"wb") as f:
            f.write(signature.to_bytes(file_content))
            f.close()
        file_dic= sqlserver.g_fileaccess(group_id)
        file_dic = json.dumps(file_dic)
        msg = des_main.encrypt(file_dic)
        msg = signature.to_str(msg)
        return msg

    if status == 15 : #获取用户加入的所有的组的表格,[15,ID]
        ID = Data[1]
        KEY = session_key[ID]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        group_dic = sqlserver.getgrouplist(ID) # group_dic = {group_id_hash:[group_name,group_cipher_id]}
        group_dic = json.dumps(group_dic)
        msg = des_main.encrypt(group_dic)
        msg = signature.to_str(msg)
        return msg

    if status == 16 : #用户请求下载组文件,[16,ID,[group_id_hash,file_id]]
        ID = Data[1]
        KEY = session_key[ID]
        data = Data[2]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        data = json.loads(data) #data = [group_id_hash,file_id]
        print(data)
        group_id = data[0]
        file_id = data[1]
        filepath = sqlserver.g_downloadfile(group_id,file_id)
        with open(filepath, 'rb') as f:
            for data in f :
                conn.sendto(data,addr)
                print(data)
        time.sleep(1)
        conn.sendto('EOF'.encode(),addr)
        msg = ['19',signature.to_sign_with_private_key('19',privateKEY)]
        return msg
    
    if status == 17 : #用户删除文件[17,ID,[file_id,group_id_hash]]
        ID = Data[1]
        KEY = session_key[ID]
        data = Data[2]
        des_main = des(str(KEY), ECB, str(KEY), padmode=PAD_PKCS5)
        data = signature.to_bytes(data)
        data = des_main.decrypt(data)
        data = json.loads(data) #data = [file_id,group_id_hash]
        file_id = data[0]
        group_id = data[1]
        filepath = sqlserver.g_deletefile(group_id,file_id)
        os.remove(filepath)
        file_dic= sqlserver.g_fileaccess(group_id)
        print(file_dic)
        file_dic = json.dumps(file_dic)
        msg = des_main.encrypt(file_dic)
        msg = signature.to_str(msg)
        return msg

if __name__ == '__main__' :
    sk = socket.socket()        # 创建socket
    host = socket.gethostname()
    host = ''
    port = 61230
    adress = (host,port)
    sk.bind(adress)            # 为socket绑定IP地址与端口号
    sk.listen(10)    # 客户端连接人数
    print("started")
    #client_hadle()
    client_handler1 = threading.Thread(target=client_handle,args=())
    client_handler1.start()
    client_handler2 = threading.Thread(target=client_handle,args=())
    client_handler2.start()
    sleep_handler1 = threading.Thread(target=sleep_handle,args=())
    sleep_handler1.start()
