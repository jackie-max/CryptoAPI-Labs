import socket

import win32crypt as w
import win32cryptcon as con

print('ЛАБОРАТОРНАЯ 2. ЗАДАНИЕ.')
print('1. Ключевая пара обмена для Б.\n2. Ключевая пара подписи для А.\n3. Генерация ключа от А.\n'
      '4. Экспорт пары на стороне Б.\n5. Экспорт пары на стороне А.\n6. Импорт ключа обмена на стороне А.\n7. Импорт ключа подписи на стороне Б.\n\n\n')
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

t = 1
def CreateNewKeyContainer(containerName, providerName, t = 1):
    # a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_NEWKEYSET)
    try:
        a = w.CryptAcquireContext(containerName, providerName, t, 0)
    except:
        a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_NEWKEYSET)
    return a

def DeleteKeyContainer(containerName, providerName, t = 1):
    a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_DELETEKEYSET)
    return a

# Возвращает список параметров провайдера
def CryptGetProvParams(providerName, containerName = None, t = 1):
    # try:
    #     a = w.CryptAcquireContext(containerName, providerName, 1, 0)
    # except:
    #     a = w.CryptAcquireContext(containerName, providerName, 1, 0x8)

    a = CreateNewKeyContainer(containerName, providerName, t)
    lst = dict()
    for i in range(50):
        try:
            val = a.CryptGetProvParam(i)
            lst[i] = val
        except:
            pass

    # a = DeleteKeyContainer(containerName, providerName, 1)
    return lst


sock = socket.socket()
sock.bind(('localhost', PORT))
sock.listen(1)
conn, ip_addr = sock.accept()
print('\nSocket connect with IP:', ip_addr)

a = w.CryptAcquireContext(containerName, providerName, t, 0)
signKeys = a.CryptGenKey(con.AT_SIGNATURE, con.CRYPT_EXPORTABLE)

print('___________________________     2     ___________________________')
print("\nКлючевая пара подписи:\n", CryptGetKeyParams(signKeys), "\n\n")
    
params = CryptGetProvParams(providerName, None)

sessionKey = a.CryptGenKey(con.CALG_RC2, con.CRYPT_EXPORTABLE)
print('___________________________     3     ___________________________')
print("Сгенерированный сессионный ключ:\n", CryptGetKeyParams(sessionKey), "\n\n")

verifyKey = signKeys.CryptExportKey(None, con.PUBLICKEYBLOB, 0)
print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>', con.PRIVATEKEYBLOB)
exportedSignKeyPair = signKeys.CryptExportKey(sessionKey, 7, 0)

print(verifyKey, "\n\n")
print(exportedSignKeyPair, "\n\n")

while True:
    data = conn.recv(1024)
    if not data:
        break
    else:
        print(data, "\n\n")
        exchangePublicKey = a.CryptImportKey(data, None, 0)
        conn.send(verifyKey)

conn.close()
print('___________________________     6     ___________________________')
print(CryptGetKeyParams(exchangePublicKey))

