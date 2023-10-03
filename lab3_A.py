import socket

import win32crypt as w
import win32cryptcon as con

print('ЛАБОРАТОРНАЯ 3. ЗАДАНИЕ.')
print('1. Открытое сообщение на стороне А.\n2. Хеш открытого сообщения.\n3. Зашифровать сообщение.\n'
      '4. Экспорт ключа на открытом ключе участника Б.\n5. Подписать хеш документа.\n6. Передать участнику Б зашифрованное сообщение.\n'
      '7. Передать Б зашифрованное сообщение. \n8. Участник Б расшифровывает сообщение \n9. Б вычисляет хеш сообщения \n\n\n')
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

# Возвращает список параметров провайдера
def CryptGetProvParams(name, containerName = None, t = 1):
    a = w.CryptAcquireContext(containerName, name, t, 0) #(Container, Provider , ProvType , Flags )
    lst = dict()
    for i in range(50):
        try:
            val = a.CryptGetProvParam(i)
            lst[i] = val
        except:
            pass
    return lst


sock = socket.socket()
sock.bind(('localhost', PORT))
sock.listen(1)
conn, ip_addr = sock.accept()

print('\nSocket connect with IP:', ip_addr)

ctx = w.CryptAcquireContext(containerName, providerName, 1, 0)
signKeys = ctx.CryptGenKey(con.AT_SIGNATURE, con.CRYPT_EXPORTABLE)
print("\nСгенированная ключевая пара подписи:\n", CryptGetKeyParams(signKeys), "\n\n")
    
params = CryptGetProvParams(providerName, None)
print("Список алгоритмов, поддерживаемых криптопровайдером:\n", params[con.PP_ENUMALGS], "\n\n")

# Зашифровать открытым ключом Б
sessionKey = ctx.CryptGenKey(con.CALG_RC2, con.CRYPT_EXPORTABLE) # Из функции CryptGetProvParams взяли CALG_RC2
print("Сгенерированный сессионный ключ:\n", CryptGetKeyParams(sessionKey), "\n\n")

verifyKey = signKeys.CryptExportKey(None, con.PUBLICKEYBLOB, 0)
exportedSignKeyPair = signKeys.CryptExportKey(sessionKey, con.PRIVATEKEYBLOB, 0)

print("Экспортируемый ключ проверки подписи:\n", verifyKey, "\n\n")
print("Экспортированная ключевая пара подписи:\n", exportedSignKeyPair, "\n\n")

data = "open message"
print('___________________________     1     ___________________________')
print("Сформированное открытое сообщение на стороне А:\n", data)
dataEncoded = bytes(data,'UTF-8')

hashObject = ctx.CryptCreateHash(con.CALG_SHA1)

encryptedData = sessionKey.CryptEncrypt(True, dataEncoded, hashObject)

sign = hashObject.CryptSignHash(con.AT_SIGNATURE)
hashVal = hashObject.CryptGetHashParam(con.HP_HASHVAL)

# print("\nЗашифрованнное сообщение:\n", encryptedData, "\n\n")
# print("Подпись хеша:\n", sign, "\n\n")
print('___________________________     2     ___________________________')
print("Хеш-значение открытого сообщения:\n", hashVal, "\n\n")
print('___________________________     3     ___________________________')
print("\nЗашифрованнное сообщение:\n", encryptedData, "\n\n")


print('___________________________     4     ___________________________')
while True:
    data = conn.recv(1024)
    if not data:
        break
    else:
        print("Полученный открытый ключ шифрования:\n", data, "\n\n")
        exchangePublicKey = ctx.CryptImportKey(data, None, 0)
        exportedSessionKey = sessionKey.CryptExportKey(exchangePublicKey, con.SIMPLEBLOB) 
        
        for message in [verifyKey, encryptedData, exportedSessionKey, sign]:
            conn.send(message)
            _ = conn.recv(1024)
       
print('___________________________     5     ___________________________')
print("Подпись хеша:\n", sign, "\n\n")

conn.close()

print('___________________________     7     ___________________________')
print("Импортированный открытый ключ шифрования:\n", CryptGetKeyParams(exchangePublicKey))



