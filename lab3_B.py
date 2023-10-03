import socket

import win32crypt as w
import win32cryptcon as con

PORT = 10000

containerName = None
providerName = 'Microsoft Enhanced Cryptographic Provider v1.0'


# Возвращает список параметров ключа
def CryptGetKeyParams(key):
    lst = dict()
    for i in range(43):
        try:
            val = key.CryptGetKeyParam(i)
            lst[i] = val
        except:
            pass
    return lst
    
 
sock = socket.socket()
sock.connect(('localhost', PORT))

ctx = w.CryptAcquireContext(containerName, providerName, 1, 0)
exchangeKey = ctx.CryptGenKey(con.AT_KEYEXCHANGE, con.CRYPT_EXPORTABLE)
print("Сгенерированная ключевая пара шифрования:\n", CryptGetKeyParams(exchangeKey), "\n\n")


print('___________________________     6     ___________________________')
publicKey = exchangeKey.CryptExportKey(None, con.PUBLICKEYBLOB, 0)
privateKey = exchangeKey.CryptExportKey(None, con.PRIVATEKEYBLOB, 0)

print("Экспортированный открытый ключ шифрования:\n", publicKey, "\n\n")
print("Экспортированная ключевая пара шифрования:\n", privateKey, "\n\n")


sock.send(publicKey)

verifyKeyStr = sock.recv(1024)
ack = bytes("ack", "UTF-8")
sock.send(ack)

print("Полученный ключ проверки подписи:\n", verifyKeyStr, "\n\n")
verifyKey = ctx.CryptImportKey(verifyKeyStr, None, 0)

encryptedData = sock.recv(1024)
sock.send(ack)

print("Полученное зашифрованное сообщение:\n", encryptedData, "\n\n")

sessionKeyStr = sock.recv(1024)
sock.send(ack)
print("Полученный сессионный ключ:\n", sessionKeyStr, "\n\n")
sessionKey = ctx.CryptImportKey(sessionKeyStr, exchangeKey)

hashObject = ctx.CryptCreateHash(con.CALG_SHA1)
data = sessionKey.CryptDecrypt(True, encryptedData, hashObject)
print('___________________________     8     ___________________________')
print("Расшифрованное сообщение:\n", str(data), "\n\n")

sign = sock.recv(1024)
sock.send(ack)
sock.close()
print("Полученная подпись:\n", sign, "\n\n")

print('___________________________     9     ___________________________')
try: 
    hashObject.CryptVerifySignature(sign, verifyKey)
    print("Расшифрование прошло успешно")
except:
    print("FAILED! Неверная подпись")
    pass





