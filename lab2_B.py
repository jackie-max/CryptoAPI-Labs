import socket

import win32crypt as w
import win32cryptcon as con

PORT = 10000

containerName = None
providerName = 'Microsoft Enhanced Cryptographic Provider v1.0'
t = 1

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

a = w.CryptAcquireContext(containerName, providerName, t, 0)
exchangeKey = a.CryptGenKey(con.AT_KEYEXCHANGE, con.CRYPT_EXPORTABLE)
print('___________________________     1     ___________________________')
print(CryptGetKeyParams(exchangeKey), "\n\n")



publicKey = exchangeKey.CryptExportKey(None, con.PUBLICKEYBLOB, 0)
privatKey = exchangeKey.CryptExportKey(None, con.PRIVATEKEYBLOB, 0)

print('___________________________     4     ___________________________')
print(publicKey, "\n\n")
print('___________________________     5     ___________________________')
print(privatKey, "\n\n")

sock.send(publicKey)
data = sock.recv(1024)
print(data, "\n\n")

sock.close()

signKey = a.CryptImportKey(data, None, 0)
print('___________________________     7     ___________________________')
print(CryptGetKeyParams(signKey))

