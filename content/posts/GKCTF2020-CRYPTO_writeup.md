---
title: "GKCTF2020 CRYPTO_writeup"
date: 2021-06-26T16:53:12+08:00
draft: false
tags: ["ctf","writeup"]
toc: true
math: false
---
GKCTF2020的密码学题目相对而言比较简单，古典密码学题目偏多。而且密码学题目也只有四道题目

![img](/images/GKCTF2020-Crypto_writeup/WechatIMG1350.jpeg)

## 0x0 小学生的密码学

打开题目描述，查看题目描述内容：

```txt
e(x)=11x+6(mod26)

密文：welcylk

（flag为base64形式）
```

看样子是仿射密码，直接逆就好了，写个python脚本解决吧：

```python
import gmpy2
import string
import base64

m = gmpy2.invert(11,26)

table = string.ascii_lowercase
# print table
cipher = "welcylk"
plainer = ""
for i in cipher:
    x = table.index(i)
    j = (x-6)*m %26
#    print j
    plainer += table[j]

flag = "flag{"+base64.b64encode(plainer) +"}"
print flag
```

运行脚本，得到flag：

```
flag{c29yY2VyeQ==}
```



## 0x1 汉字的秘密

题目描述：

```txt
你能看出汉字的奥秘吗？ 答案形式：flag{小写字母}
```

和汉字相关的密码，又是考察古典密码，估计是当铺密码

下载附件，发现附件是一个doc文件，查看附件内容：

```txt
王壮 夫工 王中 王夫 由由井 井人 夫中 夫夫 井王 土土 夫由
土夫 井中 士夫 王工 王人 土由 由口夫
```

看样子是当铺密码，没错了，写个脚本处理一下吧：

```python
dh = '田口由中人工大土士王夫井羊壮'
ds = '00123455567899'

c = '王壮 夫工 王中 王夫 由由井 井人 夫中 夫夫 井王 土土 夫由 土夫 井中 士夫 王工 王人 土由 由口夫'
s = ''
for i in c:
    if i in dh:
        s += ds[dh.index(i)]
    else:
        s += ' '
#print(s)

c_list = s.split(" ")
m = ''
for i in range(0,len(c_list)):
    m += chr(int(c_list[i])+i+1)

flag = m.lower()
print(flag)
```

运行脚本，得到flag：

```txt
flag{you_are_good}
```

------

那什么是当铺密码呢？

当铺密码是一种很有意思的密码，专门用来加密数字的，不需要密钥，明文信息包含在加密后的密文中。

它通过一个汉字中隐藏的信息：笔画数，来将汉字和数字关联起来，将汉字定义为明文，将数字定义为密文，加密是将数字映射到对应笔画的汉字，解密是将汉字按照笔画映射回数字。

有很多汉字的笔画数是相同的，所以可能会有多个明文（汉字）对应同一个密文（数字），当然这个主要是看汉字笔画映射表的选择，如果映射表只准备了9个汉字，每种笔画有一个汉字对应则是一对一的，否则是一对多的。一对一的话有个缺点就是如果要加密的明文中有重复数字，比如33，转换为“飞马”比“三三”更难总结出规律，而这种没有秘钥的加密方式重要的就是隐藏自己的规律，所以一对多会更难被破译。[1]

当铺密码就是根据汉字的特点来设计的一种古典密码，还是挺有意思的，虽然不是很实用。



## 0x2 babycrypto

下载附件，查看附件内容：

```txt
# n:0xb119849bc4523e49c6c038a509a74cda628d4ca0e4d0f28e677d57f3c3c7d0d876ef07d7581fe05a060546fedd7d061d3bc70d679b6c5dd9bc66c5bdad8f2ef898b1e785496c4989daf716a1c89d5c174da494eee7061bcb6d52cafa337fc2a7bba42c918bbd3104dff62ecc9d3704a455a6ce282de0d8129e26c840734ffd302bec5f0a66e0e6d00b5c50fa57c546cff9d7e6a978db77997082b4cb927df9847dfffef55138cb946c62c9f09b968033745b5b6868338c64819a8e92a827265f9abd409359a9471d8c3a2631b80e5b462ba42336717700998ff38536c2436e24ac19228cd2d7a909ead1a8494ff6c3a7151e888e115b68cc6a7a8c6cf8a6c005L
# e:65537
# enc:1422566584480199878714663051468143513667934216213366733442059106529451931078271460363335887054199577950679102659270179475911101747625120544429262334214483688332111552004535828182425152965223599160129610990036911146029170033592055768983427904835395850414634659565092191460875900237711597421272312032796440948509724492027247376113218678183443222364531669985128032971256792532015051829041230203814090194611041172775368357197854451201260927117792277559690205342515437625417792867692280849139537687763919269337822899746924269847694138899165820004160319118749298031065800530869562704671435709578921901495688124042302500361
# p>>128<<128:0xe4e4b390c1d201dae2c00a4669c0865cc5767bc444f5d310f3cfc75872d96feb89e556972c99ae20753e3314240a52df5dccd076a47c6b5d11b531b92d901b2b512aeb0b263bbfd624fe3d52e5e238beeb581ebe012b2f176a4ffd1e0d2aa8c4d3a2656573b727d4d3136513a931428b00000000000000000000000000000000L
```

RSA题目，考察的应该是p的高位泄露，应该是针对p的高位泄露进行设计的攻击算法来进行求解的。经查询发现，coppersmith算法应该是就是解决p高位泄露问题的解密算法，但是这个算法需要使用的开源数学工具sagemath。这里采用sagemath程序解决：

```python
n = 0xb119849bc4523e49c6c038a509a74cda628d4ca0e4d0f28e677d57f3c3c7d0d876ef07d7581fe05a060546fedd7d061d3bc70d679b6c5dd9bc66c5bdad8f2ef898b1e785496c4989daf716a1c89d5c174da494eee7061bcb6d52cafa337fc2a7bba42c918bbd3104dff62ecc9d3704a455a6ce282de0d8129e26c840734ffd302bec5f0a66e0e6d00b5c50fa57c546cff9d7e6a978db77997082b4cb927df9847dfffef55138cb946c62c9f09b968033745b5b6868338c64819a8e92a827265f9abd409359a9471d8c3a2631b80e5b462ba42336717700998ff38536c2436e24ac19228cd2d7a909ead1a8494ff6c3a7151e888e115b68cc6a7a8c6cf8a6c005L
p_fake = 0xe4e4b390c1d201dae2c00a4669c0865cc5767bc444f5d310f3cfc75872d96feb89e556972c99ae20753e3314240a52df5dccd076a47c6b5d11b531b92d901b2b512aeb0b263bbfd624fe3d52e5e238beeb581ebe012b2f176a4ffd1e0d2aa8c4d3a2656573b727d4d3136513a931428b00000000000000000000000000000000L
pbits = 1024
kbits = 128
pbar = p_fake & (2^pbits-2^kbits)
print("upper %d bits (of %d bits) is given" % (pbits-kbits, pbits))
PR.<x> = PolynomialRing(Zmod(n))
f = x + pbar
x0 = f.small_roots(X=2^kbits, beta=0.4)[0]
print(hex(int(x0 + pbar)))
```

使用sagemath运行可以得到p的数值：

```txt
0xe4e4b390c1d201dae2c00a4669c0865cc5767bc444f5d310f3cfc75872d96feb89e556972c99ae20753e3314240a52df5dccd076a47c6b5d11b531b92d901b2b512aeb0b263bbfd624fe3d52e5e238beeb581ebe012b2f176a4ffd1e0d2aa8c4d3a2656573b727d4d3136513a931428b92826225b6d0e735440b613a8336ffa3
```

然后再使用一常规的RSA脚本进行求解：

```python
import libnum

n = 0xb119849bc4523e49c6c038a509a74cda628d4ca0e4d0f28e677d57f3c3c7d0d876ef07d7581fe05a060546fedd7d061d3bc70d679b6c5dd9bc66c5bdad8f2ef898b1e785496c4989daf716a1c89d5c174da494eee7061bcb6d52cafa337fc2a7bba42c918bbd3104dff62ecc9d3704a455a6ce282de0d8129e26c840734ffd302bec5f0a66e0e6d00b5c50fa57c546cff9d7e6a978db77997082b4cb927df9847dfffef55138cb946c62c9f09b968033745b5b6868338c64819a8e92a827265f9abd409359a9471d8c3a2631b80e5b462ba42336717700998ff38536c2436e24ac19228cd2d7a909ead1a8494ff6c3a7151e888e115b68cc6a7a8c6cf8a6c005L
e = 65537
c = 1422566584480199878714663051468143513667934216213366733442059106529451931078271460363335887054199577950679102659270179475911101747625120544429262334214483688332111552004535828182425152965223599160129610990036911146029170033592055768983427904835395850414634659565092191460875900237711597421272312032796440948509724492027247376113218678183443222364531669985128032971256792532015051829041230203814090194611041172775368357197854451201260927117792277559690205342515437625417792867692280849139537687763919269337822899746924269847694138899165820004160319118749298031065800530869562704671435709578921901495688124042302500361
p = 0xe4e4b390c1d201dae2c00a4669c0865cc5767bc444f5d310f3cfc75872d96feb89e556972c99ae20753e3314240a52df5dccd076a47c6b5d11b531b92d901b2b512aeb0b263bbfd624fe3d52e5e238beeb581ebe012b2f176a4ffd1e0d2aa8c4d3a2656573b727d4d3136513a931428b92826225b6d0e735440b613a8336ffa3
q = n // p
phi = (p-1)*(q-1)
d = libnum.invmod(e,phi)
m = pow(c,d,n)
flag = libnum.n2s(m)
print flag
```

运行脚本，得到flag：

```txt
flag{3d0914a1-1e97-4822-a745-c7e20c5179b9}
```



## 0x3 Backdoor

查看题目描述：

```txt
p=k*M+(65537**a %M)
```

根据题目描述可以联想到ROCA漏洞，可以从论文中清晰地看到：

[![img](/images/GKCTF2020-Crypto_writeup/image-12.png)](/images/GKCTF2020-Crypto_writeup/image-12.png)

正好符合这个题目的hint，这个题目的考察要点应该就是[ROCA的CVE漏洞](https://crocs.fi.muni.cz/public/papers/rsa_ccs17)。这个CVE的利用再GitHub上面有现成的轮子，进行稍微修改一下就可以使用，这里给出解题的sagemath exp：[2]

```python
param = 
{
  512: {
    "n": 39,
    "a_max": 62,
    "k_max": 37,
    "M": 0x924cba6ae99dfa084537facc54948df0c23da044d8cabe0edd75bc6,
    "M_prime": 0x1b3e6c9433a7735fa5fc479ffe4027e13bea,
    "m": 5,
    "t": 6,
    "c_a": 0x80000
  },
  1024: {
    "n": 71,
    "a_max": 134,
    "k_max": 37,
    "M": 0x7923ba25d1263232812ac930e9683ac0b02180c32bae1d77aa950c4a18a4e660db8cc90384a394940593408f192de1a05e1b61673ac499416088382,
    "M_prime": 0x24683144f41188c2b1d6a217f81f12888e4e6513c43f3f60e72af8bd9728807483425d1e,
    "m": 4,
    "t": 5,
    "c_a": 0x40000000
  },
  2048: {
    "n": 126,
    "a_max": 434,
    "k_max": 53,
    "M": 0x7cda79f57f60a9b65478052f383ad7dadb714b4f4ac069997c7ff23d34d075fca08fdf20f95fbc5f0a981d65c3a3ee7ff74d769da52e948d6b0270dd736ef61fa99a54f80fb22091b055885dc22b9f17562778dfb2aeac87f51de339f71731d207c0af3244d35129feba028a48402247f4ba1d2b6d0755baff6,
    "M_prime": 0x16928dc3e47b44daf289a60e80e1fc6bd7648d7ef60d1890f3e0a9455efe0abdb7a748131413cebd2e36a76a355c1b664be462e115ac330f9c13344f8f3d1034a02c23396e6,
    "m": 7,
    "t": 8,
    "c_a": 0x400000000
  }
}

# https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/coppersmith.sage
def coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX):
    """
    Coppersmith revisited by Howgrave-Graham
    
    finds a solution if:
    * b|N, b >= N^beta , 0 < beta <= 1
    * |x| < XX
    """
    #
    # init
    #
    dd = pol.degree()
    nn = dd * mm + tt
    
    #
    # checks
    #
    if not 0 < beta <= 1 :
        raise ValueError("beta should belongs in (0, 1]")

    if not pol.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    
    #
    # Coppersmith revisited algo for univariate
    #

    # change ring of pol and x
    polZ = pol.change_ring(ZZ)
    x = polZ.parent().gen()

    # compute polynomials
    gg = []
    for ii in range(mm):
        for jj in range(dd):
            gg.append((x * XX)**jj * N**(mm - ii) * polZ(x * XX)**ii)
    for ii in range(tt):
        gg.append((x * XX)**ii * polZ(x * XX)**mm)
    
    # construct lattice B
    BB = Matrix(ZZ, nn)
    
    for ii in range(nn):
        for jj in range(ii+1):
            BB[ii, jj] = gg[ii][jj]

    # LLL
    BB = BB.LLL(early_red=True, use_siegel=True)

    # transform shortest vector in polynomial    
    new_pol = 0
    for ii in range(nn):
        new_pol += x**ii * BB[0, ii] / XX**ii

    # factor polynomial
    potential_roots = new_pol.roots()

    return [i[0] for i in potential_roots]

# Top level of the attack, feeds the queue for the workers
def roca(N):
  
  # Key is not always of perfect size, infer from size
  keylength = int(log(N, 2))
  if keylength < 1000 :
    keylength = 512
  elif  keylength < 2000 :
    keylength = 1024 
  elif keylength < 4000 :
    keylength = 2048 
  else:
    keylength = 4096 
  
  # bruteforce
  M_prime = param[keylength]['M_prime']
  c_prime = discrete_log(N, Mod(65537, M_prime))
  ord_prime = Zmod(M_prime)(65537).multiplicative_order()
  top = (c_prime + ord_prime)/2
  beta = 0.5 
  mm = param[keylength]['m']
  tt = param[keylength]['t']

  XX = int((2*pow(N, beta)) / M_prime) 

  # Bruteforce until p, q are found
  a_prime = floor(c_prime/2)
  while a_prime < top:
      
      # Construct polynomial
      m_inv = int(inverse_mod(M_prime, N))
      k_tmp = int(pow(65537, a_prime, M_prime))
      known_part_pol = int(k_tmp * m_inv)
      F = PolynomialRing(Zmod(N), implementation='NTL', names=('x',))
      (x,) = F._first_ngens(1)
      pol = x + known_part_pol
      
      # Get roots of polynomial using coppersmith
      roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)
     
      # Check if roots are p, q
      for root in roots:
        factor1 = k_tmp + abs(root) * M_prime
        if mod(N, factor1) == 0:
          factor2 = N // factor1
          return int(factor1), int(factor2)
      a_prime += 1

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import base64

with open('./pub.pem', 'r') as f:
    key = RSA.import_key(f.read())
    e = key.e
    n = key.n
print(n)
with open('flag.enc', 'r') as f:
    c = base64.b64decode(f.read())

N = n
print ("[+] Factoring %i" % N)

factor1, factor2 = roca(N)
q = factor1
p = factor2

print ("[+] Found factors of N:")
print ("[+] p =" , factor1)
print ("[+] q =" , factor2)

assert(p * q == n)
d = inverse(e, (q - 1) * (p - 1))
c = bytes_to_long(bytes.fromhex(str(c)[2:-1]))
print(long_to_bytes(pow(c, d, n)))
```

使用sagemath运行得到flag：

```txt
flag{760958c9-cca9-458b-9cbe-ea07aa1668e4}
```



## 参考：

1. [当铺密码-博客园](https://www.cnblogs.com/cc11001100/p/9357263.html#:~:text=当铺密码是一种很,加密后的密文中。)
2. [GKCTF2020 Crypto Writeup- Chrisyy's blog](https://blog.chrisyy.top/2020/05/24/gkctf/)
