from socket import *
import time
import random
import ast
import hashlib
import pyDes
import hmac
from hashlib import sha256
from pyDes import des, PAD_PKCS5, ECB
import base64
import hkdf
import rsa.prime as prime

class Client:

    def __init__(self,senderSocket,serverName,serverPort,p = 1,q = 1,SPC = 1):
        self.sender_socket = senderSocket
        self.serverName = serverName
        self.serverPort = serverPort
        self.p = p
        self.q = q       # p和q是 DH算法的参数设置，由client、server双方共享
        self.publicOfServer = 1
        self.secret_Pri_C = SPC
        self.client_Random = 1
        self.server_Random = 1
        self.preMasterKey = 1
        self.masterKey = 1
        self.session_key = 1


    def Connect(self):
        self.sender_socket.connect((self.serverName,self.serverPort))

    def terminate(self):
        self.sender_socket.close()
        print('[Client] 关闭通信套接字')


    def client_hello(self):
        print("=============TLS 握手开始=============")
        print("[Client] Hello")
        hello_dict = {}                                                 #第一次握手的报文以字典类型来进行包装
        hello_dict['Title'] = 'Client Hello'
        hello_dict['TLS Version'] = 1.3
        print("[Client] TLS Version:",hello_dict['TLS Version'])
        hello_dict['Cipher Suite'] = "TLS_RSA_DH_WITH_DES_SHA256"       # RSA用于身份验证，DH用于生成会话密钥，DES用于对称加密，SHA256用于完整性验证（MAC）
        print("[Client] Cipher Suite:", hello_dict['Cipher Suite'])       # 际采用TLS1.3的标准

        p = random.randint(800,1000)
        self.p = p
        q = random.randint(100,500)
        self.q = q
        hello_dict['DH Parameter'] = [p,q]                              # 生成用于session key生成的DH算法参数p和q，
        print("[Client] DH Parameter:", hello_dict['DH Parameter'])
        #生成自己的私钥和公钥
        secret_Pri_C = random.randint(0,p-1)
        self.secret_Pri_C = secret_Pri_C                                #更新客户自己的私钥（用于生成预主密钥）
        print("[Client] Private Key of Client:", secret_Pri_C)
        secret_Pub_C = (q ** secret_Pri_C) % p                          #生成要发送给服务器的公钥（用于生成预主密钥）
        self.secret_Pub_C = secret_Pub_C
        print("[Client] Public Key of Client:", secret_Pub_C)
        hello_dict['Public Key'] = secret_Pub_C

        # 生成客户的随机数，用于生成主密钥
        self.client_Random = prime.getprime(500)
        hello_dict['Random of Client'] = self.client_Random
        print("[Client] Random of Client:", self.client_Random)


        #发送
        Hello = str(hello_dict).encode()
        clientSocket.send(Hello)

    def hash_indentify(self,message,hash):
        data_hash = hashlib.sha256(message).digest()  # 获取收到内容的哈希值
        print("=============HASH鉴定开始=============")
        print('[Client] 服务器发来数据的哈希值：',hash)
        print('[Client] 客户计算出来的哈希值：', data_hash)
        if(data_hash == hash):
            print('[Client] 两个哈希值相等，完整性鉴定正确')
        else:
            print('[Client] 两个哈希值不等，完整性鉴定错误')
        return data_hash == hash   #返回布尔值，True代表哈希鉴定正确，False代表鉴定错误

    def des_encrypt(self,data):
        # DES_KEY = self.masterKey[0:8]
        # DES_KEY = self.sessionKeyGen()
        DES_KEY =self.session_key

        des_obj = des(DES_KEY, ECB, DES_KEY, padmode=PAD_PKCS5)  # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
        data_hash = hashlib.sha256(data).digest()       #获取传输内容的哈希值
        print("[Client] 计算要发送给服务器数据的哈希值：",data_hash)

        data = data + data_hash
        secret_bytes = des_obj.encrypt(data)
        print("[Client] 计算要发送给服务器数据的密文：", secret_bytes)
        return secret_bytes.hex()


    def des_decrypt(self,secret_bytes):
        # DES_KEY = self.masterKey[0:8]
        DES_KEY = self.session_key
        # DES_KEY = self.sessionKeyGen()
        print("[Client] 用于解密服务器内容的会话密钥：",DES_KEY)
        des_obj = des(DES_KEY, ECB, DES_KEY, padmode=PAD_PKCS5)  # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
        secret_bytes = bytes.fromhex(secret_bytes)  # 这里中文要转成字节

        s = des_obj.decrypt(secret_bytes)  # 用对象的decrypt方法解密，得到的是明文+哈希值
        print("[Client] 服务器消息解密后为（明文+哈希值的bytes形式）：",s)
        hash_data = s[-32:len(s)]
        message = s[0:-32]

        print("[Client] 明文部分:",message)
        print("[Client] 哈希值部分:", hash_data)
        return message,hash_data    #返回解密后的明文.encode()和用于验证完整性的哈希值，用以鉴定



    def data_send(self):                                                 #会话密钥协商好之后发送信息的函数
        print("=============加密通话部分开始=============")

        # DES_KEY = self.masterKey
        # des_obj = des(DES_KEY, ECB, DES_KEY, padmode=PAD_PKCS5)        # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
        data = '\nI am the client!\n平林漠漠烟如织，寒山一带伤心碧。\n暝色入高楼，有人楼上愁。\n玉阶空伫立，宿鸟归飞急。\n何处是归程？长亭更短亭。'    #要发送的文档
        secret_bytes = self.des_encrypt(data.encode())                   #对传输内容进行加密
        client_dir = {}
        client_dir['Title'] = 'Data'
        client_dir['message'] = secret_bytes                             #把要发送的内容包装成字典
        data = str(client_dir).encode()

        self.sender_socket.send(data)
        print('[Client] 已将信息发送给服务器')

    def hello_receive(self,clientSocket):
        sentence = clientSocket.recvfrom(1024)        # 从服务器接收信息

        sentence = sentence[0].decode()

        sentence = ast.literal_eval(sentence)         #把受到的内容转换成了字典类型
        if(sentence['Title'] == 'Server Hello'):
            print("[Client] 收到来自服务器的握手回复！")
            self.publicOfServer = int(sentence['Public Key'])
            print("[Client] 服务器的公钥是：",self.publicOfServer)
            self.server_Random = sentence['Random of Server']
            print("[Client] 服务器的随机数是：", self.server_Random)
        # 下面计算自己的预主密钥：
        self.preMasterKey = (int(self.publicOfServer) ** self.secret_Pri_C) % self.p

        print("[Client] 用于生成会话密钥的预主密钥是：",self.preMasterKey)
        print("=============TLS握手结束=============")

    def masterKeyGen(self):

        str1 = str(self.client_Random)    #自己的随机数
        str2 = str(self.server_Random)  #服务器的随机数
        str3 = str(self.preMasterKey)    #预主密钥

        masterkey =  base64.b64encode(hmac.new(str3.encode(),(str1+str2).encode(), digestmod=sha256).digest()).decode()
        self.masterKey = masterkey
        print("[Client] 用于生成会话密钥的主密钥是：", masterkey)
        return masterkey

    def sessionKeyGen(self):
        salt = 'guozhengkang'.encode()
        IKM = str(self.masterKey).encode()
        tmp = hkdf.hkdf_extract(salt, IKM)
        info = ''.encode()
        sessionKey = hkdf.hkdf_expand(tmp, info, 8)
        sessionKey = base64.b64encode(sessionKey).decode()[0:8]
        print('[Client] 会话密钥是:', sessionKey)
        self.session_key = sessionKey
        return sessionKey

    def read(self, dataFromServer):

        message, hashFromClient = self.des_decrypt(dataFromServer)
        flag = self.hash_indentify(message, hashFromClient)
        print("=============HASH鉴定结束=============")
        if (flag):
            print("[Client] 收到来自客户的内容并已解密和验证完整性")
            print("[Client] 解密后的明文为：",message.decode())
        else:
            print("[Client] 收到的客户消息完整性被破坏！！！！即将关闭通话！！！！")
            self.terminate()
            print("===============通话套接字已经关闭===============")


    def receive(self):
        sentence = clientSocket.recvfrom(1024)  # 从服务器接收信息
        print("[Client] 收到来自服务器的加密信息！")
        sentence = sentence[0].decode()
        sentence = ast.literal_eval(sentence)

        self.read(sentence['message'])
        print("=============加密通话部分结束=============")


serverName = '127.0.0.1' # 指定服务器IP地址
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_STREAM) # 建立TCP套接字，使用IPv4协议


Alice = Client(clientSocket,serverName,serverPort)   #生成对象
Alice.Connect()
Alice.client_hello()
time.sleep(0.5)
Alice.hello_receive(Alice.sender_socket)
time.sleep(0.5)
masterkey = Alice.masterKeyGen()
sessionkey = Alice.sessionKeyGen()
Alice.data_send()
time.sleep(0.5)
Alice.receive()
Alice.terminate()

