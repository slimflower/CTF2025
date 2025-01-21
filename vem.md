## Mô tả 

<img width="576" alt="Ảnh màn hình 2025-01-19 lúc 19 30 51" src="https://github.com/user-attachments/assets/6f5e6c32-d25f-471c-8a83-2776650f5999" />

## Giải pháp 
- Đầu tiên em sẽ phân tích code trước. Thì bài này sử dụng mô-đum tiêu chuẩn là `n=p*q` và nó liên quan đến RSA,hàm bậc 2 và AES .
- Các tham số G,p,q là các số nguyên tố ngẫu nhiên với G là 256bit và p,q là 512bit và mô-đum `n=p*q`
- Ta có hàm bậc 2 là P_x(x)= x**2 + b * x + c với b,c là các số ngẫu nhiên 64bit
- Khi đó em có giá trị `gift(a)=G**P_x(a)*mod(n)`. Với từng giá trị của a thì cho ra được 1 hàm bậc 2 P_x(A) và một giá trị gift(a).Và msg được mã hoá với key bằng thuật toán AES trong chế độ ECB. Key được tính thông qua hàm `pow(G, 2*MSG1 * MSG2, N)` và MSG1 và MSG2 là 2 giá trị đã cho sẵn .
- Vậy bây giờ để khai thác vài này và tìm flag thì em sẽ khai thác gift trước . Tính các giá trị gift ngẫu nhiên em chọn 0,1,-1 và tìm enc_flag  thì bây giờ em đã có các giá trị G(0),G(1),G(-1).

<img width="580" alt="Ảnh màn hình 2025-01-19 lúc 19 51 00" src="https://github.com/user-attachments/assets/1196d9ca-c438-4211-91b2-fc66a4d9b5ba" />

- Em nhận thấy rằng key được tính bằng luỹ thừa mô-đum với `key=G**2*MSG1*MSG2*mod(n)`. Em biến đổi nó về `key=G**2*G**MSG1*MSG2*mod(n)`. Thì bây giờ giá trị của `G**MSG1*MSG2` thông qua `MSG1 = bytes_to_long(b"Make KCSC")
MSG2 = bytes_to_long(b"Great Again")` nên chỉ còn giá trị `G**2` là em chưa biết vì vậy em sẽ đi tìm mối liên hệ của nó thông qua G(0),G(1),G(-1) như sau :

![image](https://github.com/user-attachments/assets/d841111e-9f40-4299-82b8-9f76bf6e440e)

- Em viết tay cho dễ nhìn tại phân tích này code khó nhìn ạ . Như vậy là mình đã tính được key thì em trích xuất FLAG bằng cách giải mã AES.
```py
g0= 11596356999200605720095786778809548279705110948435328820894004831120339542232002979377533000890057945707251409620559505596759173453065026029403989575675178129371710193843100186969924759458898976359180901748998446817521245038508822557602803106485801068967244020051460484768473645575455539177942817845398369442
g1= 540589447906109537068673892960157240592546236905703935033195155561453650264543585148160701603785501503565866539845057784167719568645447178297900365719068273991853423151330994382635940095282684702482317822156751060462796972386443792287859767338153217690854436144147983000923551779804970359548332282277957115
g_1= 18386161277222401618998674880860457843738536927300062794422264079282955292083484411125632582883507438021200746582370373672990049289011455715151854857344866597720093320469750282467754062121603621824956471284244649341437944630654955824879001640266454116819978504228716473787024311254775187011619088945802916658
c= bytes.fromhex("6d4cc9455f193bf4bafa5df29c810d6d29e71658d877c7c8b12b38c30f2f5d9005de55426f423339c50274dc11ea781f5bb8512070de5a6ba8c9b4e812d17f27")
n= 77936485778926792801937073384667241915349113935774850421709744143251757745018702708793685731415243927662303559986308809109390307428600616240546416885472428714814860244449930375647104565429057496673763276115230306726414352000434030670955240391180322179114793096400352284801579662025955619362342602198573194249
g2= pow(g0, -2, n)*g1*g_1%n
from Crypto.Util.number import *
MSG1 = bytes_to_long(b"Make KCSC")
MSG2 = bytes_to_long(b"Great Again")
key= pow(g2, MSG1 * MSG2, n)
key= long_to_bytes(key)[:32]
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(c))
```
- Flag : `KCSC{Congr4tulati0n_to_you_0n_5olving_chall_lor:)))}`
