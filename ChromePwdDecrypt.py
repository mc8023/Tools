# -*- coding=utf-8 -*-

# 该脚本用于导出Chrome中存储的密码
# 运行方式 python ChromePwdDecrypt.py

import os
import json
import base64
import sqlite3
import win32crypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def GetString(LocalState):
    with open(LocalState,'r',encoding='utf-8') as f:
        s=json.load(f)['os_crypt']['encrypted_key']
    return s

def pull_the_key(base64_encrypted_key):
    encrypted_key_with_header=base64.b64decode(base64_encrypted_key)
    encrypted_key=encrypted_key_with_header[5:]
    key=win32crypt.CryptUnprotectData(encrypted_key,None,None,None,0)[1]
    return key

def DecryptString(key,data):
    nonce,cipherbytes=data[3:15],data[15:]
    aesgcm=AESGCM(key)
    plainbytes=aesgcm.decrypt(nonce,cipherbytes,None)
    plaintext=plainbytes.decode('utf-8')
    return plaintext

if __name__ == '__main__':

    LocalState= os.getenv("APPDATA") + r"\..\Local\Google\Chrome\User Data\Local State"
    Data = os.getenv("APPDATA") + r"\..\Local\Google\Chrome\User Data\Default\Login Data"
    con=sqlite3.connect(Data)
    con.text_factory = bytes
    res=con.execute('SELECT action_url, username_value, password_value FROM logins').fetchall()
    con.close()
    key=pull_the_key(GetString(LocalState))
    for i in res:
        if not i[0]:
            pass
        else:
            print("action_url:" +" "+str(i[0])[1:]+"  "+"username:" +" "+i[1].decode('utf-8')+"   "+"password:" +" "+DecryptString(key, i[2]) + "  ")


