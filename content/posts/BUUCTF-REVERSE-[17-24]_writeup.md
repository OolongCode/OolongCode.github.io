---
title: "BUUCTF REVERSE [17~24]_Writeup"
date: 2022-01-28T19:24:35+08:00
draft: false
math: false
tags: ["CTF","writeup"]
toc: true
---

# BUUCTF-REVERSE-\[17-24\] writeup

8道练手的逆向题目，可以尝试做一做

![image-20210914212658475](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210914212658475.png)

## 0x0 [GWCTF 2019] pyre

应该是python逆向的题目

果然是一个pyc文件，使用pyc的逆向工具进行处理得到python的代码

```python
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: encode.py
# Compiled at: 2019-08-19 21:01:57
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[(i + 1)]

print code
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06', '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':', '\x01', 'D', ';', '%', '\x13']
# okay decompiling .\attachment.pyc
```

对代码进行审计，发现`input1`的数值没有给到，感觉应该是在`input1`里面。根据代码进行逆推

```python
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06', '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':', '\x01', 'D', ';', '%', '\x13']
l = len(code)
for i in range(l-2,-1,-1):
    code[i] = chr(ord(code[i])^ord(code[i+1]))

flag = ""
for i in range(l):
    flag += chr((ord(code[i]) - i)%128)

print(flag)
```

运行脚本，得到flag

```txt
GWHT{Just_Re_1s_Ha66y!}
```



## 0x1 rsa

rsa还能出逆向题目：D！Crypto手狂喜

两个文件，一个enc文件和一个key文件，标准的RSA文件

可以使用python脚本来获取n的数值和e的数据

```python
from Crypto.PublicKey import RSA
with open("pub.key",'r') as f:
     public_key = RSA.import_key(f.read())
     e = public_key.e
     n = public_key.n

print(n)
```

得到n的数值

```txt
86934482296048119190666062003494800588905656017203025617216654058378322103517
```

然后使用yafu工具进行大数分解，得到p和q

```txt
P = 304008741604601924494328155975272418463
Q = 285960468890451637935629440372639283459
```

然后根据后续得到是数据写脚本求解

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes,bytes_to_long
from libnum import invmod
with open("pub.key",'r') as f:
     public_key = RSA.import_key(f.read())
     e = public_key.e
     n = public_key.n

# print(n)
with open("flag.enc","rb") as f:
     c = bytes_to_long(f.read())
p = 304008741604601924494328155975272418463
q = 285960468890451637935629440372639283459

phi = (p-1)*(q-1)
d = invmod(e,phi)
m = pow(c,d,n)
flag = long_to_bytes(m)

print(flag)
```

运行脚本得到flag

```txt
b'\x02\x9d {zR\x1e\x08\xe4\xe6\x18\x06\x00flag{decrypt_256}\n'
```

flag即为

```txt
flag{decrypt_256}
```



## 0x2 [ACTF新生赛] easyre

走下流程，查下壳

![image-20210915090016298](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210915090016298.png)

发现有壳，需要进行脱壳

使用UPX进行脱壳处理

![image-20210915090432391](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210915090432391.png)

然后再次查看信息

![image-20210915090516027](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210915090516027.png)

32位程序，已经成功脱壳，可以丢进ida pro里面玩耍了

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[12]; // [esp+12h] [ebp-2Eh] BYREF
  _DWORD v5[3]; // [esp+1Eh] [ebp-22h]
  _BYTE v6[5]; // [esp+2Ah] [ebp-16h] BYREF
  int v7; // [esp+2Fh] [ebp-11h]
  int v8; // [esp+33h] [ebp-Dh]
  int v9; // [esp+37h] [ebp-9h]
  char v10; // [esp+3Bh] [ebp-5h]
  int i; // [esp+3Ch] [ebp-4h]

  __main();
  qmemcpy(v4, "*F'\"N,\"(I?+@", sizeof(v4));
  printf("Please input:");
  scanf("%s", v6);
  if ( v6[0] != 65 || v6[1] != 67 || v6[2] != 84 || v6[3] != 70 || v6[4] != 123 || v10 != 125 )
    return 0;
  v5[0] = v7;
  v5[1] = v8;
  v5[2] = v9;
  for ( i = 0; i <= 11; ++i )
  {
    if ( v4[i] != _data_start__[*((char *)v5 + i) - 1] )
      return 0;
  }
  printf("You are correct!");
  return 0;
}
```

就是非常简单的算法了，进行简单的逆向算法就可以求解，写一个python脚本进行求解

```python
data_list = [42,70,39,34,78,44,34,40,73,63,43,64]

data = r"}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)(" + chr(0x27) + r'&%$# !"'

flag_list = []

for i in data_list:
    flag_list.append(data.find(chr(i))+1)
s = [chr(x + 1) for x in pos]
flag = ''.join(s)
print ('flag{'+flag+'}')
```

运行脚本就可以得到flag：

```txt
flag{U9X_1S_W6@T?}
```



## 0x3 CrackRTF

先查一下壳

![image-20210915115948303](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210915115948303.png)

32位无壳的pe文件，使用ida pro打开文件

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  DWORD v3; // eax
  DWORD v4; // eax
  char Str[260]; // [esp+4Ch] [ebp-310h] BYREF
  int v7; // [esp+150h] [ebp-20Ch]
  char String1[260]; // [esp+154h] [ebp-208h] BYREF
  char Destination[260]; // [esp+258h] [ebp-104h] BYREF

  memset(Destination, 0, sizeof(Destination));
  memset(String1, 0, sizeof(String1));
  v7 = 0;
  printf("pls input the first passwd(1): ");
  scanf("%s", Destination);
  if ( strlen(Destination) != 6 )
  {
    printf("Must be 6 characters!\n");
    ExitProcess(0);
  }
  v7 = atoi(Destination);
  if ( v7 < 100000 )
    ExitProcess(0);
  strcat(Destination, "@DBApp");
  v3 = strlen(Destination);
  sub_40100A((BYTE *)Destination, v3, String1);
  if ( !_strcmpi(String1, "6E32D0943418C2C33385BC35A1470250DD8923A9") )
  {
    printf("continue...\n\n");
    printf("pls input the first passwd(2): ");
    memset(Str, 0, sizeof(Str));
    scanf("%s", Str);
    if ( strlen(Str) != 6 )
    {
      printf("Must be 6 characters!\n");
      ExitProcess(0);
    }
    strcat(Str, Destination);
    memset(String1, 0, sizeof(String1));
    v4 = strlen(Str);
    sub_401019((BYTE *)Str, v4, String1);
    if ( !_strcmpi("27019e688a4e62a649fd99cadaafdb4e", String1) )
    {
      if ( !(unsigned __int8)sub_40100F(Str) )
      {
        printf("Error!!\n");
        ExitProcess(0);
      }
      printf("bye ~~\n");
    }
  }
  return 0;
}
```

对代码进行审计分析，发现我们需要输入两次密码

首先看下第一次密码输入需要满足什么样的要求：

第一次输入需要进行链接然后使用md5加密然后获取的数值与某些数值相等，也就是:

````txt
MD5(xxxxxx@DBAPP) == 6E32D0943418C2C33385BC35A1470250DD8923A9
````

sub_40100A函数代码：

```c
int __cdecl sub_401230(BYTE *pbData, DWORD dwDataLen, LPSTR lpString1)
{
  int result; // eax
  DWORD i; // [esp+4Ch] [ebp-28h]
  CHAR String2[4]; // [esp+50h] [ebp-24h] BYREF
  BYTE v6[20]; // [esp+54h] [ebp-20h] BYREF
  DWORD pdwDataLen; // [esp+68h] [ebp-Ch] BYREF
  HCRYPTHASH phHash; // [esp+6Ch] [ebp-8h] BYREF
  HCRYPTPROV phProv; // [esp+70h] [ebp-4h] BYREF

  if ( !CryptAcquireContextA(&phProv, 0, 0, 1u, 0xF0000000) )
    return 0;
  if ( CryptCreateHash(phProv, 0x8004u, 0, 0, &phHash) )
  {
    if ( CryptHashData(phHash, pbData, dwDataLen, 0) )
    {
      CryptGetHashParam(phHash, 2u, v6, &pdwDataLen, 0);
      *lpString1 = 0;
      for ( i = 0; i < pdwDataLen; ++i )
      {
        wsprintfA(String2, "%02X", v6[i]);
        lstrcatA(lpString1, String2);
      }
      CryptDestroyHash(phHash);
      CryptReleaseContext(phProv, 0);
      result = 1;
    }
    else
    {
      CryptDestroyHash(phHash);
      CryptReleaseContext(phProv, 0);
      result = 0;
    }
  }
  else
  {
    CryptReleaseContext(phProv, 0);
    result = 0;
  }
  return result;
}
```

程序直接调用WIN32的API函数进行调用来进行MD5的加密

使用在线的[MD5工具](https://www.somd5.com/)进行解密获得：

```txt
123321@DBApp
```

下面解决一下第二次加密的问题，第二次加密显然也是一个MD5的比较问题，即：

```txt
MD5(xxxxxx123321@DBApp@DBAPP) == 27019e688a4e62a649fd99cadaafdb4e
```

同样使用上面那个MD5的工具进行求解就可以得到数据：

```txt
~!3a@0123321@DBApp
```

现在得到了所有的密码，是不是可以运行一下程序来得到结果：

运行程序得到了一个rtf文件，打开rtf文件就能得到flag啦：

```txt
Flag{N0_M0re_Free_Bugs}
```



## 0x4 [2019红帽杯] easyRE

得到一个ELF文件，可以确定是Linux系统的文件，虽然Linux系统的大多数文件是不带壳的，但是为了以防万一还是查下程序信息：

![image-20210918150158372](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210918150158372.png)

64位程序，果然是没有壳的程序。使用x64 IDA pro打开一下程序，看看程序内部

```c
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, int a3)
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  void *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  sub_401BC0(
    (unsigned int)sub_4009C6,
    v4,
    (unsigned int)&retaddr,
    (unsigned int)sub_402080,
    (unsigned int)sub_402110,
    a3,
    (__int64)&v5);
}
```

好像是找不到什么具体的内容，使用字符串检索定位到关键函数的位置

```c
__int64 sub_4009C6()
{
  __int64 result; // rax
  int i; // [rsp+Ch] [rbp-114h]
  __int64 v2; // [rsp+10h] [rbp-110h]
  __int64 v3; // [rsp+18h] [rbp-108h]
  __int64 v4; // [rsp+20h] [rbp-100h]
  __int64 v5; // [rsp+28h] [rbp-F8h]
  __int64 v6; // [rsp+30h] [rbp-F0h]
  __int64 v7; // [rsp+38h] [rbp-E8h]
  __int64 v8; // [rsp+40h] [rbp-E0h]
  __int64 v9; // [rsp+48h] [rbp-D8h]
  __int64 v10; // [rsp+50h] [rbp-D0h]
  __int64 v11; // [rsp+58h] [rbp-C8h]
  char v12[13]; // [rsp+60h] [rbp-C0h] BYREF
  char v13[4]; // [rsp+6Dh] [rbp-B3h] BYREF
  char v14[19]; // [rsp+71h] [rbp-AFh] BYREF
  char v15[32]; // [rsp+90h] [rbp-90h] BYREF
  int v16; // [rsp+B0h] [rbp-70h]
  char v17; // [rsp+B4h] [rbp-6Ch]
  char v18[72]; // [rsp+C0h] [rbp-60h] BYREF
  unsigned __int64 v19; // [rsp+108h] [rbp-18h]

  v19 = __readfsqword(0x28u);
  qmemcpy(v12, "Iodl>Qnb(ocy", 12);
  v12[12] = 127;
  qmemcpy(v13, "y.i", 3);
  v13[3] = 127;
  qmemcpy(v14, "d`3w}wek9{iy=~yL@EC", sizeof(v14));
  memset(v15, 0, sizeof(v15));
  v16 = 0;
  v17 = 0;
  sub_4406E0(0LL, v15, 37LL);
  v17 = 0;
  if ( sub_424BA0(v15) == 36 )
  {
    for ( i = 0; i < (unsigned __int64)sub_424BA0(v15); ++i )
    {
      if ( (unsigned __int8)(v15[i] ^ i) != v12[i] )
      {
        result = 4294967294LL;
        goto LABEL_13;
      }
    }
    sub_410CC0("continue!");
    memset(v18, 0, 0x40uLL);
    v18[64] = 0;
    sub_4406E0(0LL, v18, 64LL);
    v18[39] = 0;
    if ( sub_424BA0(v18) == 39 )
    {
      v2 = sub_400E44(v18);
      v3 = sub_400E44(v2);
      v4 = sub_400E44(v3);
      v5 = sub_400E44(v4);
      v6 = sub_400E44(v5);
      v7 = sub_400E44(v6);
      v8 = sub_400E44(v7);
      v9 = sub_400E44(v8);
      v10 = sub_400E44(v9);
      v11 = sub_400E44(v10);
      if ( !(unsigned int)sub_400360(v11, off_6CC090) )
      {
        sub_410CC0("You found me!!!");
        sub_410CC0("bye bye~");
      }
      result = 0LL;
    }
    else
    {
      result = 4294967293LL;
    }
  }
  else
  {
    result = 0xFFFFFFFFLL;
  }
LABEL_13:
  if ( __readfsqword(0x28u) != v19 )
    sub_444020();
  return result;
}
```

找到关键函数，下面就是对关键函数进行分析来寻找线索

简单对代码进行审计，可以发现有很多混淆来防止我们进行正确的逆向分析操作

来，让我们跳进第一个坑：

```c
 v19 = __readfsqword(0x28u);
  qmemcpy(v12, "Iodl>Qnb(ocy", 12);
  v12[12] = 127;
  qmemcpy(v13, "y.i", 3);
  v13[3] = 127;
  qmemcpy(v14, "d`3w}wek9{iy=~yL@EC", sizeof(v14));
  memset(v15, 0, sizeof(v15));
  v16 = 0;
  v17 = 0;
  sub_4406E0(0LL, v15, 37LL);
  v17 = 0;
  if ( sub_424BA0(v15) == 36 )
  {
    for ( i = 0; i < (unsigned __int64)sub_424BA0(v15); ++i )
    {
      if ( (unsigned __int8)(v15[i] ^ i) != v12[i] )
      {
        result = 4294967294LL;
        goto LABEL_13;
      }
    }
    sub_410CC0("continue!");
```

写一个python脚本迭代出假flag：

```python
data = []
v12 = "Iodl>Qnb(ocy"
insert_v = 127;
v13 = "y.i"
v14 = "d`3w}wek9{iy=~yL@EC"
flag = ""
for i in v12:
    data.append(ord(i))
data.append(insert_v)
for i in v13:
    data.append(ord(i))
data.append(insert_v)
for i in v14:
    data.append(ord(i))

for i in range(36):
    flag +=chr(data[i]^i)

print(flag)
```

运行脚本得到fake flag：

```txt
Info:The first four chars are `flag`
```

然后走进下面一个坑：

（”吾愿称之为base64之坑“ XD ）

![image-20210918163713879](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210918163713879.png)

提取数据：

```txt
Vm0wd2VHUXhTWGhpUm1SWVYwZDRWVll3Wkc5WFJsbDNXa1pPVlUxV2NIcFhhMk0xVmpKS1NHVkdXbFpOYmtKVVZtcEtTMUl5VGtsaVJtUk9ZV3hhZVZadGVHdFRNVTVYVW01T2FGSnRVbGhhVjNoaFZWWmtWMXBFVWxSTmJFcElWbTAxVDJGV1NuTlhia0pXWWxob1dGUnJXbXRXTVZaeVdrWm9hVlpyV1hwV1IzaGhXVmRHVjFOdVVsWmlhMHBZV1ZSR1lWZEdVbFZTYlhSWFRWWndNRlZ0TVc5VWJGcFZWbXR3VjJKSFVYZFdha1pXWlZaT2NtRkhhRk5pVjJoWVYxZDBhMVV3TlhOalJscFlZbGhTY1ZsclduZGxiR1J5VmxSR1ZXSlZjRWhaTUZKaFZqSktWVkZZYUZkV1JWcFlWV3BHYTFkWFRrZFRiV3hvVFVoQ1dsWXhaRFJpTWtsM1RVaG9hbEpYYUhOVmJUVkRZekZhY1ZKcmRGTk5Wa3A2VjJ0U1ExWlhTbFpqUldoYVRVWndkbFpxUmtwbGJVWklZVVprYUdFeGNHOVhXSEJIWkRGS2RGSnJhR2hTYXpWdlZGVm9RMlJzV25STldHUlZUVlpXTlZadE5VOVdiVXBJVld4c1dtSllUWGhXTUZwell6RmFkRkpzVWxOaVNFSktWa1phVTFFeFduUlRhMlJxVWxad1YxWnRlRXRXTVZaSFVsUnNVVlZVTURrPQ==
```

进行十次base64解密得到一个博客地址：https://bbs.pediy.com/thread-254172.htm

点开博客看一下，可以看到这段话：

```txt

所谓“让对手不要走正确的破解之路” 

讲人话 就是“把对手往沟里带” 

但对手并不傻 很多时候攻击方比防守方更聪明 

要想带对手进沟 防守方必须首先透彻了解攻击方 特别是其人性弱点（知道为什么是马克思主义学院了吧） 
```

Good, 现在知道自己掉坑里面了， 两个坑都掉了一遍所以flag在哪呢？

我们去找下主函数

![image-20210918173639284](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210918173639284.png)

发现周围存在一个奇奇怪怪的函数，会不会就是这个函数呢

点开看看：

```c
unsigned __int64 sub_400D35()
{
  unsigned __int64 result; // rax
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  int i; // [rsp+10h] [rbp-20h]
  int j; // [rsp+14h] [rbp-1Ch]
  unsigned int v4; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v1 = sub_43FD20(0LL) - qword_6CEE38;
  for ( i = 0; i <= 1233; ++i )
  {
    sub_40F790(v1);
    sub_40FE60();
    sub_40FE60();
    v1 = sub_40FE60() ^ 0x98765432;
  }
  v4 = v1;
  if ( ((unsigned __int8)v1 ^ byte_6CC0A0[0]) == 102 && (HIBYTE(v4) ^ (unsigned __int8)byte_6CC0A3) == 103 )
  {
    for ( j = 0; j <= 24; ++j )
      sub_410E90((unsigned __int8)(byte_6CC0A0[j] ^ *((_BYTE *)&v4 + j % 4)));
  }
  result = __readfsqword(0x28u) ^ v5;
  if ( result )
    sub_444020();
  return result;
}
```

应该就是简单的异或操作了，需要提取数据来进行异或来得到flag

提取数据并写一个异或脚本就就可以得到flag

```python
data = [
  0x40, 0x35, 0x20, 0x56, 0x5D, 0x18, 0x22, 0x45, 0x17, 0x2F, 
  0x24, 0x6E, 0x62, 0x3C, 0x27, 0x54, 0x48, 0x6C, 0x24, 0x6E, 
  0x72, 0x3C, 0x32, 0x45, 0x5B
  ]
s = "flag"
key = ''
flag = ''

for i in range(4):
    key += chr(ord(s[i])^data[i])

for i in range(len(data)):
    flag += chr(data[i]^ord(key[i%4]))

print(flag)
```

运行脚本就能得到flag，终于是over了

```txt
flag{Act1ve_Defen5e_Test}
```



## 0x5 [ACTF新生赛2020] rome

首先，查一下文件的信息

![image-20210919081555684](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210919081555684.png)

32位程序，没有壳，丢进IDA prio里面看看：

```c
int func()
{
  int result; // eax
  int v1[4]; // [esp+14h] [ebp-44h]
  unsigned __int8 v2; // [esp+24h] [ebp-34h] BYREF
  unsigned __int8 v3; // [esp+25h] [ebp-33h]
  unsigned __int8 v4; // [esp+26h] [ebp-32h]
  unsigned __int8 v5; // [esp+27h] [ebp-31h]
  unsigned __int8 v6; // [esp+28h] [ebp-30h]
  int v7; // [esp+29h] [ebp-2Fh]
  int v8; // [esp+2Dh] [ebp-2Bh]
  int v9; // [esp+31h] [ebp-27h]
  int v10; // [esp+35h] [ebp-23h]
  unsigned __int8 v11; // [esp+39h] [ebp-1Fh]
  char v12[29]; // [esp+3Bh] [ebp-1Dh] BYREF

  strcpy(v12, "Qsw3sj_lz4_Ujw@l");
  printf("Please input:");
  scanf("%s", &v2);
  result = v2;
  if ( v2 == 65 )
  {
    result = v3;
    if ( v3 == 67 )
    {
      result = v4;
      if ( v4 == 84 )
      {
        result = v5;
        if ( v5 == 70 )
        {
          result = v6;
          if ( v6 == 123 )
          {
            result = v11;
            if ( v11 == 125 )
            {
              v1[0] = v7;
              v1[1] = v8;
              v1[2] = v9;
              v1[3] = v10;
              *(_DWORD *)&v12[17] = 0;
              while ( *(int *)&v12[17] <= 15 )
              {
                if ( *((char *)v1 + *(_DWORD *)&v12[17]) > 64 && *((char *)v1 + *(_DWORD *)&v12[17]) <= 90 )
                  *((_BYTE *)v1 + *(_DWORD *)&v12[17]) = (*((char *)v1 + *(_DWORD *)&v12[17]) - 51) % 26 + 65;
                if ( *((char *)v1 + *(_DWORD *)&v12[17]) > 96 && *((char *)v1 + *(_DWORD *)&v12[17]) <= 122 )
                  *((_BYTE *)v1 + *(_DWORD *)&v12[17]) = (*((char *)v1 + *(_DWORD *)&v12[17]) - 79) % 26 + 97;
                ++*(_DWORD *)&v12[17];
              }
              *(_DWORD *)&v12[17] = 0;
              while ( *(int *)&v12[17] <= 15 )
              {
                result = (unsigned __int8)v12[*(_DWORD *)&v12[17]];
                if ( *((_BYTE *)v1 + *(_DWORD *)&v12[17]) != (_BYTE)result )
                  return result;
                ++*(_DWORD *)&v12[17];
              }
              result = printf("You are correct!");
            }
          }
        }
      }
    }
  }
  return result;
}
```

对代码进行简单的审计，可以发现，程序的加密算法是类似与凯撒加密的位移方式，可以根据程序的这一特点写个Python脚本进行求解来得到flag的数据：

```python
import string

data = [81,115,119,51,115,106,95,108,122,52,95,85,106,119,64,108]

Lower = string.ascii_lowercase
Upper = string.ascii_uppercase

flag = ""

for i in data:
    if i > 64 and i <= 90:
        flag += Upper[i-14-65]
    elif i > 96 and i <= 122:
        flag += Lower[i-18-97]
    else:
        flag += chr(i)
print ('flag{'+flag+'}')
```

运行脚本，得到flag：

```txt
flag{Cae3ar_th4_Gre@t}
```



## 0x6 [FlareOn4] login

发现文件是一个html文件，应该是需要进行源码阅读的题目，然后逆向算法

```html
<!DOCTYPE Html />
<html>

<head>
    <title>FLARE On 2017</title>
</head>

<body>
    <input type="text" name="flag" id="flag" value="Enter the flag" />
    <input type="button" id="prompt" value="Click to check the flag" />
    <script type="text/javascript">
        document.getElementById("prompt").onclick = function () {
            var flag = document.getElementById("flag").value;
            var rotFlag = flag.replace(/[a-zA-Z]/g, function (c) { 
                return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26); 
            });
            if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
                alert("Correct flag!");
            } else {
                alert("Incorrect flag, rot again");
            }
        }
    </script>
</body>

</html>
```

源码的核心逻辑是在JavaScript的代码中，看来题目要求我们可以能够对算法进行逆向分析，来得到flag数据

代码进行的操作无非就是±13的操作。

代码会区分大小写分别进行相应的操作来得到flag，如果字母+13小于字母表最后一位字母，字母最终就+13，否则字母最终就-13。逻辑非常简单，写个简单的逆向算法就能进行求解：

```python
cipher = "PyvragFvqrYbtvafNerRnfl@syner-ba.pbz"
m = ""
for i in cipher:
    if ord(i) >= 65 and ord(i) <= 90:
        if ord(i)-13 < 65:
            m += chr(ord(i)+13)
        else:
            m += chr(ord(i)-13)
    elif ord(i) >= 97 and ord(i) <= 122:
        if ord(i)-13 < 97:
            m += chr(ord(i)+13)
        else:
            m += chr(ord(i)-13)
    else:
        m += i

print(m)
```

运行脚本，就能得到flag：

```txt
ClientSideLoginsAreEasy@flare-on.com
```

唔~题目好像还有个hint可以看一下：

```txt
Hint:本题解出相应字符串后请用flag{}包裹，形如：flag{123456@flare-on.com}
```

所以，这道题目的flag应该就是：

```txt
flag{ClientSideLoginsAreEasy@flare-on.com}
```



## 0x7 [GUET-CTF2019] re

拿到程序，先看看程序的信息：

![image-20210919092405673](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210919092405673.png)

发现程序有壳，而且是一个64位的ELF程序

需要进行脱壳处理，程序使用的是最基本的UPX的壳，可以使用UPX进行简单脱壳：

```powershell
upx -d re
```

脱壳后，然后使用Exeinfo再次进行查看

![image-20210919092939620](/images/BUUCTF-REVERSE-[17-24]_writeup/image-20210919092939620.png)

壳已经被脱掉，然后使用x64 IDA pro进行查看程序

```c
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, int a3)
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  void *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  sub_4016C0(
    (unsigned int)sub_400E28,
    v4,
    (unsigned int)&retaddr,
    (unsigned int)sub_401B80,
    (unsigned int)sub_401C10,
    a3,
    (__int64)&v5);
}
```

发现程序入口并找不到什么东西，应该是将入口函数进行混淆和隐藏了

使用字符串检索来获取相应的信息，来定位到主函数：

```c
__int64 __fastcall sub_400E28(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // er8
  int v9; // er9
  __int64 result; // rax
  __int64 v11; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v12; // [rsp+28h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  sub_40F950((unsigned int)"input your flag:", a2, a3, a4, a5, a6, 0LL, 0LL, 0LL, 0LL);
  sub_40FA80((unsigned int)"%s", (unsigned int)&v11, v6, v7, v8, v9, v11);
  if ( (unsigned int)sub_4009AE(&v11) )
    sub_410350("Correct!");
  else
    sub_410350("Wrong!");
  result = 0LL;
  if ( __readfsqword(0x28u) != v12 )
    sub_443550();
  return result;
}
```

主函数中的一些关键性的函数都被进行了混淆操作，代码进行审计分析

v11是关键输入函数，然后`sub_40FA80`是关键性的函数，对`sub_40FA80`分析：

```c
_BOOL8 __fastcall sub_4009AE(char *a1)
{
  if ( 1629056 * *a1 != 166163712 )
    return 0LL;
  if ( 6771600 * a1[1] != 731332800 )
    return 0LL;
  if ( 3682944 * a1[2] != 357245568 )
    return 0LL;
  if ( 10431000 * a1[3] != 1074393000 )
    return 0LL;
  if ( 3977328 * a1[4] != 489211344 )
    return 0LL;
  if ( 5138336 * a1[5] != 518971936 )
    return 0LL;
  if ( 7532250 * a1[7] != 406741500 )
    return 0LL;
  if ( 5551632 * a1[8] != 294236496 )
    return 0LL;
  if ( 3409728 * a1[9] != 177305856 )
    return 0LL;
  if ( 13013670 * a1[10] != 650683500 )
    return 0LL;
  if ( 6088797 * a1[11] != 298351053 )
    return 0LL;
  if ( 7884663 * a1[12] != 386348487 )
    return 0LL;
  if ( 8944053 * a1[13] != 438258597 )
    return 0LL;
  if ( 5198490 * a1[14] != 249527520 )
    return 0LL;
  if ( 4544518 * a1[15] != 445362764 )
    return 0LL;
  if ( 3645600 * a1[17] != 174988800 )
    return 0LL;
  if ( 10115280 * a1[16] != 981182160 )
    return 0LL;
  if ( 9667504 * a1[18] != 493042704 )
    return 0LL;
  if ( 5364450 * a1[19] != 257493600 )
    return 0LL;
  if ( 13464540 * a1[20] != 767478780 )
    return 0LL;
  if ( 5488432 * a1[21] != 312840624 )
    return 0LL;
  if ( 14479500 * a1[22] != 1404511500 )
    return 0LL;
  if ( 6451830 * a1[23] != 316139670 )
    return 0LL;
  if ( 6252576 * a1[24] != 619005024 )
    return 0LL;
  if ( 7763364 * a1[25] != 372641472 )
    return 0LL;
  if ( 7327320 * a1[26] != 373693320 )
    return 0LL;
  if ( 8741520 * a1[27] != 498266640 )
    return 0LL;
  if ( 8871876 * a1[28] != 452465676 )
    return 0LL;
  if ( 4086720 * a1[29] != 208422720 )
    return 0LL;
  if ( 9374400 * a1[30] == 515592000 )
    return 5759124 * a1[31] == 719890500;
  return 0LL;
}
```

写个C语言的flag生成器来生成flag

```c
#include <stdio.h>

int main()
{
  char a1[30] = {0};
  *a1 = 166163712 / 1629056;
  a1[1] = 731332800 / 6771600;
  a1[2] = 357245568 / 3682944;
  a1[3] = 1074393000 / 10431000;
  a1[4] = 489211344 / 3977328;
  a1[5] = 518971936 / 5138336;
  a1[7] = 406741500 / 7532250;
  a1[8] = 294236496 / 5551632;
  a1[9] = 177305856 / 3409728;
  a1[10] = 650683500 / 13013670;
  a1[11] = 298351053 / 6088797;
  a1[12] = 386348487 / 7884663;
  a1[13] = 438258597 / 8944053;
  a1[14] = 249527520 / 5198490;
  a1[15] = 445362764 / 4544518;
  a1[17] = 174988800 / 3645600;
  a1[16] = 981182160 / 10115280;
  a1[18] = 493042704 / 9667504;
  a1[19] = 257493600 / 5364450;
  a1[20] = 767478780 / 13464540;
  a1[21] = 312840624 / 5488432;
  a1[22] = 1404511500 / 14479500;
  a1[23] = 316139670 / 6451830;
  a1[24] = 619005024 / 6252576;
  a1[25] = 372641472 / 7763364;
  a1[26] = 373693320 / 7327320;
  a1[27] = 498266640 / 8741520;
  a1[28] = 452465676 / 8871876;
  a1[29] = 208422720 / 4086720;
  a1[30] = 515592000 / 9374400;
  a1[31] = 719890500 / 5759124;
  for(int i=0;i<32;++i)
    {
      if(a1[i] == 0) printf("*");
      else printf("%c",a1[i]);
    }
  printf("\n");
}
```

编译并运行来得到flag：

```txt
flag{e*65421110ba03099a1c039337}
```

由于有一位的字符未知，需要进行爆破来得到flag:

```txt
flag{e165421110ba03099a1c039337}
```
