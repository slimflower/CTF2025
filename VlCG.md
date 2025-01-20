## Mô tả 
```py=

from Crypto.Util.number import *
from hashlib import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from secret import flag

class LCG():
    
    def __init__(self, seed, a, c, m):
        self.seed = seed
        self.a = a
        self.c = c
        self.m = m
        self.state = seed
        
    def next(self):
        
        self.seed = (self.a * self.seed ** 65537 + self.c) % m
        return self.seed >> 20
    
a = getPrime(50)
c = getPrime(50)
m = getPrime(100)
seed = getRandomInteger(50)

lcg = LCG(seed, a, c, m)

key = sha256(long_to_bytes(seed)).digest()
enc = AES.new(key, AES.MODE_ECB).encrypt(pad(flag, 16))

hint = []

print(f"{enc = }")
print(f"{a = }")
print(f"{c = }")
print(f"{m = }")
print(f"{lcg.next() = }")

"""
enc = b'\x17j\x1b\xb1(eWHD\x98\t\xfc\x04\x94(\x18\xeaxT\xa6B*\xa0E\xe92\xe36!3\xbc\x96[\xa5\x82eG\xc2\x00\x7fM\xf0\xcb@tN\xf8\x01'      
a = 758872855643059
c = 814446603569537
m = 984792769709730047935594905989
lcg.next() = 241670272469283782290680
"""
```
## Giải pháp 
- Phân tích code thì em thấy enc được được mã hoá bằng AES ở chế độ ECB với key được hash từ giá trị seed được tính bằng LCG . Vì vậy để giải flag phải tìm được giá trị của seed để tính ra key 
- Vậy để tìm seed ta sẽ tìm seed.netx() . Mà `>> 20` sẽ làm mất 20 bit cuối của seed.next thế nên sẽ cộng lại 20 bit cho giá trị lcg.next

![image](https://github.com/user-attachments/assets/694b216b-bfa6-428d-a3ed-ed13ebb4ca38)


- Mà giá trị của seed_netx ban đầu bị mất 20 bit nên em sẽ sử dụng brute force chạy từ 1 đến 2**20+1 để thử tất cả các giá trị seed và kiểm tra flag nếu hợp lệ `b"KCSC{"` thì break .

```py
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes

enc = b'\x17j\x1b\xb1(eWHD\x98\t\xfc\x04\x94(\x18\xeaxT\xa6B*\xa0E\xe92\xe36!3\xbc\x96[\xa5\x82eG\xc2\x00\x7fM\xf0\xcb@tN\xf8\x01'
a = 758872855643059
c = 814446603569537
m = 984792769709730047935594905989
leak = 241670272469283782290680


phi = m - 1
e = 65537
d = pow(e, -1, phi)

leak_shifted = leak << 20


for i in range(1, 2**20 + 1):
    try:
        
        seed_next = (leak_shifted + i - c) * pow(a, -1, m) % m
        seed = pow(seed_next, d, m)

        
        key = SHA256.new(long_to_bytes(seed)).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_flag = cipher.decrypt(enc)

        if b"KCSC{" in decrypted_flag:
            print(f"Found flag: {decrypted_flag}")
            break
    except Exception as ex:
        continue
```
- Flag : `KCSC{linear_congruential_generator(LCG)}`

