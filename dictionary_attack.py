import time

import hashing_sha256 as sha256
import hashing_bcrypt as bcrypt

def attack(leaked_hashed_password, hashing):
    # https://www.teamsid.com/worst-passwords-2015/
    dictionary = ['123456', 'password', '12345678', 'qwerty', '12345', 
                '123456789', 'football', '1234', '1234567', 'baseball', 
                'welcome', '1234567890', 'abc123', '111111', '1qaz2wsx', 
                'dragon', 'master', 'monkey', 'letmein', 'login', 'princess', 
                'qwertyuiop', 'solo', 'passw0rd', 'starwars']
            
    for p in dictionary:
        if hashing.check_password(leaked_hashed_password, p):
            return '当たり！パスワードは {} です。'.format(p)
    else:
        return 'はずれ(´・ω・｀)'


passwords = ['complex.password'] * 9 + ['passw0rd']

print('sha256')
leaked_sha256 = [sha256.hash_password(p) for p in passwords]
st = time.time()
for i, v in enumerate(leaked_sha256):
    result = attack(v, sha256)
    print('user{:02d}: {}'.format(i, result))
print('Total time: {:.3f} s'.format(time.time()-st))

print('bcrypt-5')
leaked_bcrypt = [bcrypt.hash_password(p, 5) for p in passwords]
st = time.time()
for i, v in enumerate(leaked_bcrypt):
    result = attack(v, bcrypt)
    #print('user{:02d}: {}'.format(i, result))
print('Total time: {:.3f} s'.format(time.time()-st))

print('bcrypt-12')
leaked_bcrypt = [bcrypt.hash_password(p) for p in passwords]
st = time.time()
for i, v in enumerate(leaked_bcrypt):
    result = attack(v, bcrypt)
    #print('user{:02d}: {}'.format(i, result))
print('Total time: {:.3f} s'.format(time.time()-st))

