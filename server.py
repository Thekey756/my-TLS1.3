import time
from socket import *
import ast
import random
import hmac
from hashlib import sha256
from pyDes import des, PAD_PKCS5, ECB
import base64
import hashlib
import hkdf
import rsa.prime as prime

class Server:
   def __init__(self,receiveSocket,p = 1,q = 1,PS = 1,SPC = 1):
      self.receive_socket = receiveSocket
      self.p = p
      self.q = q
      self.publicOfClient = PS
      self.secret_Pri_S = 1    #自己的私钥
      self.secret_Pub_S = 1    #自己的公钥
      self.client_Random = 1
      self.server_Random = 1
      self.preMasterKey = 1
      self.masterKey = 1
      self.session_key = 1
      self.connectionSocket = None
      self.addr_client = None


   def server_hello(self,hello_dir_client,connectionSocket):
      self.p = hello_dir_client['DH Parameter'][0]
      self.q = hello_dir_client['DH Parameter'][1]
      self.publicOfClient = hello_dir_client['Public Key']
      self.client_Random = hello_dir_client['Random of Client']

      print('[Server] TLS Version:',hello_dir_client['TLS Version'])
      print('[Server] Cipher Suite:',hello_dir_client['Cipher Suite'])
      print('[Server] DH Parameter:', hello_dir_client['DH Parameter'])
      print('[Server] Public Key of Client:',hello_dir_client['Public Key'])
      print('[Server] Random of Client:', hello_dir_client['Random of Client'])


      #生成自己的私钥和公钥并把公钥传给client
      secret_Pri_S = random.randint(0, self.p - 1)
      self.secret_Pri_S = secret_Pri_S  # 更新自己的私钥
      secret_Pub_S = (self.q ** secret_Pri_S) % self.p
      self.secret_Pub_S =secret_Pub_S
      self.server_Random = prime.getprime(500)
      print('[Server] Private Key of Server:', self.secret_Pri_S)
      print('[Server] Public Key of Server:', self.secret_Pub_S)
      print("[Server] Random of Server:", self.server_Random)

      hello_dir = {}
      hello_dir['Title'] = "Server Hello"
      hello_dir['Public Key'] = secret_Pub_S      #把自己的公钥包含进要回复给client的包里面
      hello_dir['Random of Server'] = self.server_Random
      hello_dir['Cipher Suite'] = "TLS_RSA_DH_WITH_DES_SHA256"
      hello_dir = str(hello_dir).encode()

      connectionSocket.send(hello_dir)
      print("[Server] 已回复Client的Hello握手!!")

      #最后生成自己的预主密钥:
      self.preMasterKey = (self.publicOfClient ** self.secret_Pri_S) % self.p

      print("[Server] 用于生成会话密钥的预主密钥是:",self.preMasterKey)
      print("=============TLS 握手结束=============")



   def des_encrypt(self, data):
      # DES_KEY = self.masterKey[0:8]
      # DES_KEY = self.sessionKeyGen()
      DES_KEY = self.session_key
      des_obj = des(DES_KEY, ECB, DES_KEY, padmode=PAD_PKCS5)  # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
      data_hash = hashlib.sha256(data).digest()  # 获取传输内容的哈希值

      print("[Server] 计算要发送给客户的 数据的哈希值：", data_hash)
      data = data + data_hash

      secret_bytes = des_obj.encrypt(data)
      print("[Server] 计算要发送给客户的数据的密文：", secret_bytes)

      return secret_bytes.hex()

   def hash_indentify(self, message, hash):
      data_hash = hashlib.sha256(message).digest()  # 获取收到内容的哈希值

      print("=============HASH鉴定开始=============")
      print('[Server] 服务器发来数据的哈希值：', hash)
      print('[Server] 客户计算出来的哈希值：', data_hash)
      if (data_hash == hash):
         print('[Server] 两个哈希值相等，完整性鉴定正确')
      else:
         print('[Server] 两个哈希值不等，完整性鉴定错误')

      return data_hash == hash  # 返回布尔值，True代表哈希鉴定正确，False代表鉴定错误

   def des_decrypt(self, secret_bytes):
      # DES_KEY = self.masterKey[0:8]
      # DES_KEY = self.sessionKeyGen()
      DES_KEY = self.session_key
      des_obj = des(DES_KEY, ECB, DES_KEY, padmode=PAD_PKCS5)  # 初始化一个des对象，参数是秘钥，加密方式，偏移， 填充方式
      secret_bytes = bytes.fromhex(secret_bytes)  # 这里中文要转成字节
      s = des_obj.decrypt(secret_bytes)  # 用对象的decrypt方法解密，得到的是明文+哈希值
      print("[Server] 客户发来的消息解密后为（明文+哈希值的bytes形式）：", s)
      hash_data = s[-32:len(s)]
      message = s[0:-32]
      print("[Server] 明文部分:", message)
      print("[Server] 哈希值部分:", hash_data)

      return message, hash_data  # 返回解密后的明文和用于验证完整性的哈希值，用以鉴定


   def read(self,dataFromClient):

      message,hashFromClient = self.des_decrypt(dataFromClient)
      flag = self.hash_indentify(message,hashFromClient)
      print("=============HASH鉴定结束=============")
      if(flag):
         print("[Server] 收到来自客户的内容并已解密和验证完整性")
         print("[Server] 解密后的明文为：",message.decode())
      else:
         print("[Server] 收到的客户消息完整性被破坏！！！！即将关闭通话！！！！")
         self.terminate()
         print("===============通话套接字已经关闭===============")





   def start(self):
      self.connectionSocket, self.addr = self.receive_socket.accept()  # 接收到客户连接请求后，建立新的TCP连接套接字
      print("=============TLS 握手开始=============")
      print('[Server] Accept new connection from %s:%s...' % self.addr)


   def terminate(self):
      self.connectionSocket.close()
      print('[Server] 关闭通信套接字')


   def receive(self):
      while True:
         sentence = self.connectionSocket.recv(2048)  # 获取客户发送的字符串
         sentence = sentence.decode()
         sentence = ast.literal_eval(sentence)

         choice = sentence['Title']
         if(choice == 'Client hello'):
            self.server_hello(sentence,self.connectionSocket)
         elif(choice == 'Data'):
            self.read(str(sentence['message']))
         return sentence

   def masterKeyGen(self):

      str1 = str(self.client_Random)     # 客户的公钥
      str2 = str(self.server_Random)     # 服务器的公钥
      str3 = str(self.preMasterKey)      # 预主密钥
      masterkey = base64.b64encode(hmac.new(str3.encode(), (str1 + str2).encode(), digestmod=sha256).digest()).decode()

      self.masterKey = masterkey
      print("[Server] 用于生成会话密钥的主密钥是：", masterkey)
      # print("=============加密通话部分开始=============")
      return masterkey

   def sessionKeyGen(self):
      salt = 'guozhengkang'.encode()
      IKM = str(self.masterKey).encode()
      tmp = hkdf.hkdf_extract(salt, IKM)
      info = ''.encode()
      sessionKey = hkdf.hkdf_expand(tmp, info, 8)
      sessionKey = base64.b64encode(sessionKey).decode()[0:8]
      print('[Server] 会话密钥是:', sessionKey)
      self.session_key = sessionKey
      print("=============加密通话部分开始=============")
      return sessionKey

   def response(self,connectionSocket):
      data = '\nI am the server!\n须菩提！忍辱波罗蜜，如来说非忍辱波罗蜜，是名忍辱波罗蜜。何以故？须菩提！' \
             '如我昔为歌利王割截身体，我于尔时，无我相、无人相、无众生相、无寿者相。何以故？' \
             '我于往昔节节支解时，若有我相、人相、众生相、寿者相，应生嗔恨。'.encode() # 要回复的文档
      secret_bytes = self.des_encrypt(data)  # 对传输内容进行加密

      client_dir = {}
      client_dir['Title'] = 'Response'
      client_dir['message'] = secret_bytes  # 把要发送的内容包装成字典
      data = str(client_dir).encode()

      connectionSocket.send(data)
      print('[Server] 已将回复消息发送给客户')
      print("=============加密通话部分结束=============")




serverPort = 12000
serverSocket = socket(AF_INET, SOCK_STREAM) # 创建TCP欢迎套接字，使用IPv4协议
serverSocket.bind(('',serverPort)) # 将TCP欢迎套接字绑定到指定端口
serverSocket.listen(1) # 最大连接数为1
print("[Server] Ready to receive")


Bob = Server(serverSocket)
Bob.start()
sentence =  Bob.receive()
time.sleep(0.5)
Bob.server_hello(sentence,Bob.connectionSocket)
time.sleep(0.5)
masterkey = Bob.masterKeyGen()
session_key = Bob.sessionKeyGen()
sentence =  Bob.receive()
time.sleep(0.5)
Bob.response(Bob.connectionSocket)
Bob.terminate()
