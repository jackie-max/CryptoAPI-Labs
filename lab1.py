import win32crypt as w
import win32cryptcon as con

print('ЛАБОРАТОРНАЯ 2. ЗАДАНИЕ.')
print('1. Список типов криптопровайдеров.\n2. Список криптопровайдеров.\n3. Перечислитьсписок основных параметров и алгоритмов.\n'
      '4. Получение контекста+ создание ключевого контейнера.\n5. Удаление контейнера.\n\n\n')

print('___________________________     1     ___________________________')
print("\nТипы криптопровайдеров:\n", w.CryptEnumProviderTypes())


def CryptEnamProviderByType(t):
    lst_provs = w.CryptEnumProviders()
    list = []
    for name, i in lst_provs:
        if i == t:
            list.append(name)
    return list

t = 1
print('___________________________     2     ___________________________')
print("\nКриптопровайдеры:\n", w.CryptEnumProviders())
print("\nКриптопровайдеры с типом =", t, ":\n", CryptEnamProviderByType(t))

def CreateNewKeyContainer(containerName, providerName, t = 1):
    # a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_NEWKEYSET)
    try:
        a = w.CryptAcquireContext(containerName, providerName, 1, 0)
    except:
        a = w.CryptAcquireContext(containerName, providerName, 1, con.CRYPT_NEWKEYSET)
    return a

def DeleteKeyContainer(containerName, providerName, t = 1):
    a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_DELETEKEYSET)
    return a

containerName = 'test_container'
print(">>>>>>>>>>>>>>>", con.CRYPT_NEWKEYSET)
print(">>>>>>>>>>>>>>>", con.CRYPT_DELETEKEYSET)

def CryptGetProvParams(providerName, containerName = None, t = 1):
    # try:
    #     a = w.CryptAcquireContext(containerName, providerName, 1, 0)
    # except:
    #     a = w.CryptAcquireContext(containerName, providerName, 1, 0x8)

    a = CreateNewKeyContainer(containerName, providerName, 1)
    lst = dict()
    for i in range(50):
        try:
            val = a.CryptGetProvParam(i)
            lst[i] = val
        except:
            pass

    # a = DeleteKeyContainer(containerName, providerName, 1)
    return lst
providerName = 'Microsoft Enhanced Cryptographic Provider v1.0'
params = CryptGetProvParams(providerName, None, t)


# def CreateNewKeyContainer(containerName, providerName, t = 1):
#     # a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_NEWKEYSET)
#     try:
#         a = w.CryptAcquireContext(containerName, providerName, 1, 0)
#     except:
#         a = w.CryptAcquireContext(containerName, providerName, 1, con.CRYPT_NEWKEYSET)
#     return a
#
# def DeleteKeyContainer(containerName, providerName, t = 1):
#     a = w.CryptAcquireContext(containerName, providerName, t, con.CRYPT_DELETEKEYSET)
#     return a


print('___________________________     3     ___________________________')
print("\nПараметры", providerName, ":\n", params)
print("\nАлгоритмы", providerName, ":\n", params[con.PP_ENUMALGS])
print('___________________________     4     ___________________________')
print("\nКонтейнер", containerName, "\n")

# ctx = CreateNewKeyContainer(containerName, providerName, t)
print("Текущий контейнер:\n", CryptGetProvParams(providerName, containerName, t)[con.PP_CONTAINER])

print("Список ключевых контейнеров:\n", CryptGetProvParams(providerName, None, t)[con.PP_ENUMCONTAINERS])
print('___________________________     5     ___________________________')
print("\nУдаление ключевого контейнера с именем", containerName, "\n")
a = DeleteKeyContainer(containerName, providerName, 1)

print("Список ключевых контейнеров:\n", CryptGetProvParams(providerName, None, t)[con.PP_ENUMCONTAINERS])
