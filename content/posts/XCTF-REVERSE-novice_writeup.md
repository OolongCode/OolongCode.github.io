---
title: "XCTF REVERSE novice_writeup"
date: 2021-10-14T13:27:13+08:00
draft: false
math: false
tags: ["ctf","writeup"]
toc: true
---

# XCTF-REVERSE-新手区 writeup

来XCTF平台，做做Re练练手

![image-20210902134256690](/images/XCTF-REVERSE-novice_writeup/image-20210902134256690.png)

XCTF平台有十道题目：

![image-20210902134352010](/images/XCTF-REVERSE-novice_writeup/image-20210902134352010.png)

十道题目应该是涵盖了逆向方向的主要内容，带着好奇心去探索逆向的世界吧

## 0x0 insanity

往往第一道题目都不是很难，下载附件，看看是个什么东西。

文件没有扩展名，可能是个ELF文件，走个流程

首先查一下壳

![image-20210902135713948](/images/XCTF-REVERSE-novice_writeup/image-20210902135713948.png)

果然是ELF格式的文件，不过不是x64格式的ELF文件

使用IDA pro打开文件，查看主函数的反编译代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned int v4; // eax

  puts("Reticulating splines, please wait..");
  sleep(5u);
  v3 = time(0);
  srand(v3);
  v4 = rand();
  puts((&strs)[v4 % 0xA]);
  return 0;
}
```

跟进strs的数据

![image-20210902145813017](/images/XCTF-REVERSE-novice_writeup/image-20210902145813017.png)

继续跟进strs的数据

![image-20210902145852653](/images/XCTF-REVERSE-novice_writeup/image-20210902145852653.png)

get到了flag

```txt
9447{This_is_a_flag}
```



## 0x1 python-trade

看题目应该是一个Python的逆向题目

文件是一个pyc文件应该是Python的逆向文件，可以使用Python的反编译工具进行反编译

可以使用 `uncompyle` 进行反编译：

```python
# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.8.8 (default, Apr 13 2021, 15:08:03) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: 1.py
# Compiled at: 2017-06-03 10:20:43
import base64

def encode(message):
    s = ''
    for i in message:
        x = ord(i) ^ 32
        x = x + 16
        s += chr(x)

    return base64.b64encode(s)


correct = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'
flag = ''
print 'Input flag:'
flag = raw_input()
if encode(flag) == correct:
    print 'correct'
else:
    print 'wrong'
# okay decompiling .\test.pyc
```

应该是需要逆这个加密算法的进行求解，密码手的老本行了，写个求解脚本:

```python
import base64

def Redecode(cipher):
    message = ''
    cipher = base64.b64decode(cipher).decode()
    for i in cipher:
        x = ord(i) - 16
        x = x ^ 32
        message += chr(x)

    return message

cipher = 'XlNkVmtUI1MgXWBZXCFeKY+AaXNt'

flag = Redecode(cipher)
print(flag)
```

在python2环境下运行脚本，就能得到flag了：

```txt
nctf{d3c0mpil1n9_PyC}
```



## 0x2 re1

附件有报毒，麻了

走一下流程，先查文件信息

![image-20210902152537015](/images/XCTF-REVERSE-novice_writeup/image-20210902152537015.png)

32位的可执行程序，程序没有壳，丢进IDA pro进行静态分析

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  __m128i v5; // [esp+0h] [ebp-44h] BYREF
  char v6[8]; // [esp+10h] [ebp-34h] BYREF
  int v7; // [esp+18h] [ebp-2Ch]
  __int16 v8; // [esp+1Ch] [ebp-28h]
  char v9[32]; // [esp+20h] [ebp-24h] BYREF

  v5 = _mm_loadu_si128((const __m128i *)"DUTCTF{We1c0met0DUTCTF}");
  v7 = 0;
  strcpy(v6, "DUTCTF}");
  v8 = 0;
  printf("欢迎来到DUTCTF呦\n");
  printf("这是一道很可爱很简单的逆向题呦\n");
  printf("输入flag吧:");
  scanf("%s", v9);
  v3 = strcmp(v5.m128i_i8, v9);
  if ( v3 )
    v3 = v3 < 0 ? -1 : 1;
  if ( v3 )
    printf(aFlag_0);
  else
    printf(aFlagGet);
  system("pause");
  return 0;
}
```

首先，我们需要知道具体的逻辑判断形式，逻辑判断是以什么形式进行判断的，找到逻辑判断语句

```c
if ( v3 )
    v3 = v3 < 0 ? -1 : 1;
if ( v3 )
    printf(aFlag_0);
else
    printf(aFlagGet);
```

`v3` 数值不为0的情况下会先执行第一个 `if` 语句，将不正确的v3值进行转换

然后再进行一个`if - else ` 的逻辑语句，判断`v3`的数值，如果`v3`的数值是等于`0`的，那么我们输入的flag就是正确的

那么，`v3` 是什么东西？

```c
v3 = strcmp(v5.m128i_i8, v9);
```

是一个比较数值，如果 `v5.m128i_i8` 与 `v9` 相等，那么`v3` 的数值就等于0了，逻辑现在搞通了，下面跟进数据：

![image-20210902155119211](/images/XCTF-REVERSE-novice_writeup/image-20210902155119211.png)

这段数据应该就是 `v5 `的数据了，将数据转换成字符串

![image-20210902155219566](/images/XCTF-REVERSE-novice_writeup/image-20210902155219566.png)

成功得到flag：

```txt
DUTCTF{We1c0met0DUTCTF}
```



## 0x3 game

应该是个游戏，感觉还是挺有意思的

![image-20210902160124008](/images/XCTF-REVERSE-novice_writeup/image-20210902160124008.png)

果然是一个游戏，还蛮有意思的，不过，还是要走下流程查一下信息

![image-20210902160325396](/images/XCTF-REVERSE-novice_writeup/image-20210902160325396.png)

32位程序，没有壳，先丢进IDA pro康一康

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  int i; // [esp+DCh] [ebp-20h]
  int v5; // [esp+F4h] [ebp-8h] BYREF

  sub_45A7BE(&unk_50B110);
  sub_45A7BE(&unk_50B158);
  sub_45A7BE(&unk_50B1A0);
  sub_45A7BE(&unk_50B1E8);
  sub_45A7BE(&unk_50B230);
  sub_45A7BE(&unk_50B278);
  sub_45A7BE(&unk_50B2C0);
  sub_45A7BE(&unk_50B308);
  sub_45A7BE("二                                                     |\n");
  sub_45A7BE("|              by 0x61                                 |\n");
  sub_45A7BE("|                                                      |\n");
  sub_45A7BE("|------------------------------------------------------|\n");
  sub_45A7BE(
    "Play a game\n"
    "The n is the serial number of the lamp,and m is the state of the lamp\n"
    "If m of the Nth lamp is 1,it's on ,if not it's off\n"
    "At first all the lights were closed\n");
  sub_45A7BE("Now you can input n to change its state\n");
  sub_45A7BE(
    "But you should pay attention to one thing,if you change the state of the Nth lamp,the state of (N-1)th and (N+1)th w"
    "ill be changed too\n");
  sub_45A7BE("When all lamps are on,flag will appear\n");
  sub_45A7BE("Now,input n \n");
  while ( 1 )
  {
    while ( 1 )
    {
      sub_45A7BE("input n,n(1-8)\n");
      sub_459418();
      sub_45A7BE("n=");
      sub_4596D4("%d", &v5);
      sub_45A7BE("\n");
      if ( v5 >= 0 && v5 <= 8 )
        break;
      sub_45A7BE("sorry,n error,try again\n");
    }
    if ( v5 )
    {
      sub_4576D6(v5 - 1);
    }
    else
    {
      for ( i = 0; i < 8; ++i )
      {
        if ( (unsigned int)i >= 9 )
          sub_458919();
        byte_532E28[i] = 0;
      }
    }
    sub_4581B7("CLS");
    sub_458054();
    if ( byte_532E28[0] == 1
      && byte_532E28[1] == 1
      && byte_532E28[2] == 1
      && byte_532E28[3] == 1
      && byte_532E28[4] == 1
      && byte_532E28[5] == 1
      && byte_532E28[6] == 1
      && byte_532E28[7] == 1 )
    {
      sub_457AB4();
    }
  }
}
```

寻找到核心代码：

```c
if ( byte_532E28[0] == 1
      && byte_532E28[1] == 1
      && byte_532E28[2] == 1
      && byte_532E28[3] == 1
      && byte_532E28[4] == 1
      && byte_532E28[5] == 1
      && byte_532E28[6] == 1
      && byte_532E28[7] == 1 )
    {
      sub_457AB4();
    }
```

可以知道，可以确定是 `sub_457AB4();` 函数：

```c
int sub_45E940()
{
  char v1; // [esp+0h] [ebp-164h]
  int i; // [esp+D0h] [ebp-94h]
  char v3[22]; // [esp+DCh] [ebp-88h] BYREF
  char v4[32]; // [esp+F2h] [ebp-72h] BYREF
  char v5[4]; // [esp+112h] [ebp-52h] BYREF
  char v6[64]; // [esp+120h] [ebp-44h]

  sub_45A7BE((int)"done!!! the flag is ", v1);
  v6[0] = 18;
  v6[1] = 64;
  v6[2] = 98;
  v6[3] = 5;
  v6[4] = 2;
  v6[5] = 4;
  v6[6] = 6;
  v6[7] = 3;
  v6[8] = 6;
  v6[9] = 48;
  v6[10] = 49;
  v6[11] = 65;
  v6[12] = 32;
  v6[13] = 12;
  v6[14] = 48;
  v6[15] = 65;
  v6[16] = 31;
  v6[17] = 78;
  v6[18] = 62;
  v6[19] = 32;
  v6[20] = 49;
  v6[21] = 32;
  v6[22] = 1;
  v6[23] = 57;
  v6[24] = 96;
  v6[25] = 3;
  v6[26] = 21;
  v6[27] = 9;
  v6[28] = 4;
  v6[29] = 62;
  v6[30] = 3;
  v6[31] = 5;
  v6[32] = 4;
  v6[33] = 1;
  v6[34] = 2;
  v6[35] = 3;
  v6[36] = 44;
  v6[37] = 65;
  v6[38] = 78;
  v6[39] = 32;
  v6[40] = 16;
  v6[41] = 97;
  v6[42] = 54;
  v6[43] = 16;
  v6[44] = 44;
  v6[45] = 52;
  v6[46] = 32;
  v6[47] = 64;
  v6[48] = 89;
  v6[49] = 45;
  v6[50] = 32;
  v6[51] = 65;
  v6[52] = 15;
  v6[53] = 34;
  v6[54] = 18;
  v6[55] = 16;
  v6[56] = 0;
  v3[0] = 123;
  v3[1] = 32;
  v3[2] = 18;
  v3[3] = 98;
  v3[4] = 119;
  v3[5] = 108;
  v3[6] = 65;
  v3[7] = 41;
  v3[8] = 124;
  v3[9] = 80;
  v3[10] = 125;
  v3[11] = 38;
  v3[12] = 124;
  v3[13] = 111;
  v3[14] = 74;
  v3[15] = 49;
  v3[16] = 83;
  v3[17] = 108;
  v3[18] = 94;
  v3[19] = 108;
  v3[20] = 84;
  v3[21] = 6;
  qmemcpy(v4, "`S,yhn _uec{", 12);
  v4[12] = 127;
  v4[13] = 119;
  v4[14] = 96;
  v4[15] = 48;
  v4[16] = 107;
  v4[17] = 71;
  v4[18] = 92;
  v4[19] = 29;
  v4[20] = 81;
  v4[21] = 107;
  v4[22] = 90;
  v4[23] = 85;
  v4[24] = 64;
  v4[25] = 12;
  v4[26] = 43;
  v4[27] = 76;
  v4[28] = 86;
  v4[29] = 13;
  v4[30] = 114;
  v4[31] = 1;
  strcpy(v5, "u~");
  for ( i = 0; i < 56; ++i )
  {
    v3[i] ^= v6[i];
    v3[i] ^= 0x13u;
  }
  return sub_45A7BE((int)"%s\n", (char)v3);
}
```

基本上可以确定在这里输出flag，基本逻辑应该可以清晰的知道

下面使用Ollydbg进行动态调试，调试出来flag

![image-20210909174908510](/images/XCTF-REVERSE-novice_writeup/image-20210909174908510.png)

先使用F8进行单步调试，确定关键函数位置

![image-20210909195648745](/images/XCTF-REVERSE-novice_writeup/image-20210909195648745.png)

F7进入函数的具体执行过程，进行字符串检索

![image-20210909195755383](/images/XCTF-REVERSE-novice_writeup/image-20210909195755383.png)

找到输入的关键位置，然后移动到关键位置

![image-20210909195839072](/images/XCTF-REVERSE-novice_writeup/image-20210909195839072.png)

根据已知的逻辑循环，修改逻辑循环

![image-20210909200656065](/images/XCTF-REVERSE-novice_writeup/image-20210909200656065.png)

修改这个关键性的跳转代码进行跳转修改，将跳转修改为call那个位置

修改为：

```assembly
jnz short 00D2F66C
```

然后运行修改过汇编的程序

尝试输入几个参数就能获取到flag了

![image-20210909201014405](/images/XCTF-REVERSE-novice_writeup/image-20210909201014405.png)

得到flag

```txt
zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}
```



## 0x4 Hello, CTF

首先查一下程序信息

![image-20210909201418156](/images/XCTF-REVERSE-novice_writeup/image-20210909201418156.png)

32位没有壳的程序

使用IDA pro的看一下程序

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // ebx
  char v4; // al
  int result; // eax
  int v6; // [esp+0h] [ebp-70h]
  int v7; // [esp+0h] [ebp-70h]
  char Buffer[2]; // [esp+12h] [ebp-5Eh] BYREF
  char v9[20]; // [esp+14h] [ebp-5Ch] BYREF
  char v10[32]; // [esp+28h] [ebp-48h] BYREF
  __int16 v11; // [esp+48h] [ebp-28h]
  char v12; // [esp+4Ah] [ebp-26h]
  char v13[36]; // [esp+4Ch] [ebp-24h] BYREF

  strcpy(v13, "437261636b4d654a757374466f7246756e");
  while ( 1 )
  {
    memset(v10, 0, sizeof(v10));
    v11 = 0;
    v12 = 0;
    sub_40134B(aPleaseInputYou, v6);
    scanf("%s", v9);
    if ( strlen(v9) > 0x11 )
      break;
    for ( i = 0; i < 17; ++i )
    {
      v4 = v9[i];
      if ( !v4 )
        break;
      sprintf(Buffer, "%x", v4);
      strcat(v10, Buffer);
    }
    if ( !strcmp(v10, v13) )
      sub_40134B(aSuccess, v7);
    else
      sub_40134B(aWrong, v7);
  }
  sub_40134B(aWrong, v7);
  result = --Stream._cnt;
  if ( Stream._cnt < 0 )
    return _filbuf(&Stream);
  ++Stream._ptr;
  return result;
}
```

代码非常清晰，应该可以明确v13的值和flag应该是一致的

v13应该是Hex编码的字符串，进行解码就得到flag了

```txt
CrackMeJustForFun
```



## 0x5 open-source

下载附件，源代码审计，看看源代码内容

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
    	printf("what?\n");
    	exit(1);
    }

    unsigned int first = atoi(argv[1]);
    if (first != 0xcafe) {
    	printf("you are wrong, sorry.\n");
    	exit(2);
    }

    unsigned int second = atoi(argv[2]);
    if (second % 5 == 3 || second % 17 != 8) {
    	printf("ha, you won't get it!\n");
    	exit(3);
    }

    if (strcmp("h4cky0u", argv[3])) {
    	printf("so close, dude!\n");
    	exit(4);
    }

    printf("Brr wrrr grr\n");

    unsigned int hash = first * 31337 + (second % 17) * 11 + strlen(argv[3]) - 1615810207;

    printf("Get your key: ");
    printf("%x\n", hash);
    return 0;
}
```

根据源码进行求解，其实也就是解个方程

可以写个C程序直接求解

```c
#include <stdio.h>
#include <string.h>

int main() {
    unsigned int first =  0xcafe;

    unsigned int second = 25;
    char * Third = "h4cky0u";

    unsigned int hash = first * 31337 + (second % 17) * 11 + strlen(Third) - 1615810207;

    printf("Get your key: ");
    printf("%x\n", hash);
    return 0;
}
```

编译并运行程序就能得到flag：

```txt
Get your key: c0ffee
```



## 0x6 simple-unpack

看题目，应该是一个有壳的程序

就正常走一下流程首先先要看看程序的信息

![image-20210910132745520](/images/XCTF-REVERSE-novice_writeup/image-20210910132745520.png)

加壳的64位的程序，首先使用upx脱一下壳，然后使用x64 IDA pro查看

![image-20210910133500403](/images/XCTF-REVERSE-novice_writeup/image-20210910133500403.png)

直接就能看到flag信息数据

```txt
flag{Upx_1s_n0t_a_d3liv3r_c0mp4ny}
```



## 0x7 logmein

查一下程序信息

![image-20210910133947331](/images/XCTF-REVERSE-novice_writeup/image-20210910133947331.png)

没有壳，64位的Linux程序

直接进行x64 ida pro静态调试

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  size_t v3; // rsi
  int i; // [rsp+3Ch] [rbp-54h]
  char s[36]; // [rsp+40h] [rbp-50h] BYREF
  int v6; // [rsp+64h] [rbp-2Ch]
  __int64 v7; // [rsp+68h] [rbp-28h]
  char v8[28]; // [rsp+70h] [rbp-20h] BYREF
  int v9; // [rsp+8Ch] [rbp-4h]

  v9 = 0;
  strcpy(v8, ":\"AL_RT^L*.?+6/46");
  v7 = 0x65626D61726168LL;
  v6 = 7;
  printf("Welcome to the RC3 secure password guesser.\n");
  printf("To continue, you must enter the correct password.\n");
  printf("Enter your guess: ");
  __isoc99_scanf("%32s", s);
  v3 = strlen(s);
  if ( v3 < strlen(v8) )
    sub_4007C0();
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( i >= strlen(v8) )
      sub_4007C0();
    if ( s[i] != (char)(*((_BYTE *)&v7 + i % v6) ^ v8[i]) )
      sub_4007C0();
  }
  sub_4007F0();
}
```

应该是对算法进行逆向来得到相应的flag

关键的数据是v7和v8，针对这两个数据写个C程序进行逆向算法

```c
#include <stdio.h>
#include <string.h>
int main()
{
        char v8[28];
        strcpy(v8, ":\"AL_RT^L*.?+6/46");
        char *v7 = "harambe";
        int v6 = 7;
        char s[strlen(v8)];
        for (int i = 0; i < strlen(v8); ++i )
        {
                s[i] = *(v7+i % v6) ^ v8[i];
        }
        printf("%s\n",s);
}
```

编译并运行得到flag

```txt
RC3-2016-XORISGUD
```



## 0x8 no-string-attached

查一下文件的信息

![image-20210910153107869](/images/XCTF-REVERSE-novice_writeup/image-20210910153107869.png)

32位文件，没有壳，丢进到IDA pro查看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setlocale(6, &locale);
  banner();
  prompt_authentication();
  authenticate();
  return 0;
}
```

进行分析，确定flag应该是在 `authenticate()`函数中

跟进到 `authenticate()`函数

```c
void authenticate()
{
  wchar_t ws[8192]; // [esp+1Ch] [ebp-800Ch] BYREF
  wchar_t *s2; // [esp+801Ch] [ebp-Ch]

  s2 = (wchar_t *)decrypt((wchar_t *)&s, (wchar_t *)&dword_8048A90);
  if ( fgetws(ws, 0x2000, stdin) )
  {
    ws[wcslen(ws) - 1] = 0;
    if ( !wcscmp(ws, s2) )
      wprintf(&unk_8048B44);
    else
      wprintf(&unk_8048BA4);
  }
  free(s2);
}
```

关键数据应该是在s2中，调用了decrypt函数，看一下这个函数的汇编代码

```assembly
ws= dword ptr -800Ch
s2= dword ptr -0Ch

; __unwind {
push    ebp
mov     ebp, esp
sub     esp, 8028h
mov     dword ptr [esp+4], offset dword_8048A90 ; wchar_t *
mov     dword ptr [esp], offset s ; s
call    decrypt
mov     [ebp+s2], eax
mov     eax, ds:stdin@@GLIBC_2_0
mov     [esp+8], eax    ; stream
mov     dword ptr [esp+4], 2000h ; n
lea     eax, [ebp+ws]
mov     [esp], eax      ; ws
call    _fgetws
test    eax, eax
jz      short loc_804879C
```

根据汇编代码，应该可以清晰的知道，flag数据应该是存储在eax寄存器中了

使用gdb动态调试程序

```shell
gdb Re_demo
```

然后设置断点，根据刚刚了解到的信息，flag的数据应该是在decrypt函数中，设置断点

```gdb
b decrypt
```

然后运行程序到断点

```gdb
r
```

然后单步执行

```gdb
n
```

查看寄存器

```gdb
i r
```

![image-20210910155818798](/images/XCTF-REVERSE-novice_writeup/image-20210910155818798.png)

然后查看eax寄存器存储的数据

```gdb
x/sw $eax
```

![image-20210910155914675](/images/XCTF-REVERSE-novice_writeup/image-20210910155914675.png)

成功拿到flag数据

```txt
9447{you_are_an_international_mystery}
```



## 0x9 getit

基本流程，查看程序信息

![image-20210910160228522](/images/XCTF-REVERSE-novice_writeup/image-20210910160228522.png)

64位无壳的ELF可执行程序

先丢进x64 IDA pro看一看

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // al
  int i; // [rsp+0h] [rbp-40h]
  int j; // [rsp+4h] [rbp-3Ch]
  FILE *stream; // [rsp+8h] [rbp-38h]
  char filename[24]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v9; // [rsp+28h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( (i & 1) != 0 )
      v3 = 1;
    else
      v3 = -1;
    *(&t + i + 10) = s[i] + v3;
  }
  strcpy(filename, "/tmp/flag.txt");
  stream = fopen(filename, "w");
  fprintf(stream, "%s\n", u);
  for ( j = 0; j < strlen(&t); ++j )
  {
    fseek(stream, p[j], 0);
    fputc(*(&t + p[j]), stream);
    fseek(stream, 0LL, 0);
    fprintf(stream, "%s\n", u);
  }
  fclose(stream);
  remove(filename);
  return 0;
}
```

应该是一个文件写入的程序，打开一个文件并进行写入

 对程序进行分析应该可以看出三个部分

1. 初始化变量
2. 生成flag数据
3. 写入flag数据

查看一下静态数据：

![image-20210911072552068](/images/XCTF-REVERSE-novice_writeup/image-20210911072552068.png)

根据静态数据和对代码分析的结果，写一个flag生成器：

```c
#include <stdio.h>
#include <string.h>
int main()
{
        char t[] =" harifCTF{????????????????????????????????}";
        char s[] = "c61b68366edeb7bdce3c6820314b7498";
        t[0] = 0x53;
        int i, v3;
        for ( i = 0; i < strlen(s); ++i )
        {
                if ( (i & 1) != 0 )
                        v3 = 1;
                else
                        v3 = -1;
                *(t+i+10) = s[i]+v3;
        }
        printf("%s\n",t);
        return 0;
}
```

编译并运行flag生成器就可以生成flag啦！

```txt
SharifCTF{b70c59275fcfa8aebf2d5911223c6589}
```



## 0xA csaw2013reversing2

杀软会报毒的程序，首先查一下壳

![image-20210911082611406](/images/XCTF-REVERSE-novice_writeup/image-20210911082611406.png)

32位无壳程序，使用IDA pro查看详细信息

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  CHAR *lpMem; // [esp+8h] [ebp-Ch]
  HANDLE hHeap; // [esp+10h] [ebp-4h]

  hHeap = HeapCreate(0x40000u, 0, 0);
  lpMem = (CHAR *)HeapAlloc(hHeap, 8u, SourceSize + 1);
  memcpy_s(lpMem, SourceSize, &unk_409B10, SourceSize);
  if ( !sub_40102A() && !IsDebuggerPresent() )
  {
    MessageBoxA(0, lpMem + 1, "Flag", 2u);
    HeapFree(hHeap, 0, lpMem);
    HeapDestroy(hHeap);
    ExitProcess(0);
  }
  __debugbreak();
  sub_401000(v3 + 4, lpMem);
  ExitProcess(0xFFFFFFFF);
}
```

都是WIN32api的调用，尝试运行一下程序：

![image-20210911084558336](/images/XCTF-REVERSE-novice_writeup/image-20210911084558336.png)

应该是有些关键的语句没有执行

可以查看下IDA pro的汇编语句

![image-20210913082559422](/images/XCTF-REVERSE-novice_writeup/image-20210913082559422.png)

显然是有一个Flag没有进行相应的跳转，显然有着较大的嫌疑，可以尝试去搞一搞让其跳转

使用OD进行调试修改汇编让其进行跳转，首先定位到Flag

```txt
000D1092   .  85C0          test    eax, eax
000D1094      74 23         je      short 000D10B9
000D1096   >  41            inc     ecx
000D1097   .  41            inc     ecx
000D1098   .  41            inc     ecx
000D1099   .  41            inc     ecx
000D109A      CC            int3
000D109B   .  8B55 F4       mov     edx, dword ptr [ebp-C]
000D109E   .  E8 5DFFFFFF   call    000D1000
000D10A3      EB 4A         jmp     short 000D10EF
000D10A5   .  6A 02         push    2                                ; /Style = MB_ABORTRETRYIGNORE|MB_APPLMODAL
000D10A7   .  68 20780D00   push    000D7820                         ; |Title = "Flag"
000D10AC   .  FF75 F4       push    dword ptr [ebp-C]                ; |Text
000D10AF   .  6A 00         push    0                                ; |hOwner = NULL
000D10B1   .  FF15 E4600D00 call    dword ptr [<&USER32.MessageBoxA>>; \MessageBoxA
000D10B7   .  EB 14         jmp     short 000D10CD
000D10B9   >  6A 02         push    2                                ; /Style = MB_ABORTRETRYIGNORE|MB_APPLMODAL
000D10BB   .  68 20780D00   push    000D7820                         ; |Title = "Flag"
000D10C0   .  8B45 F4       mov     eax, dword ptr [ebp-C]           ; |
000D10C3   .  40            inc     eax                              ; |
000D10C4   .  50            push    eax                              ; |Text
000D10C5   .  6A 00         push    0                                ; |hOwner = NULL
000D10C7   .  FF15 E4600D00 call    dword ptr [<&USER32.MessageBoxA>>; \MessageBoxA
```

然后定位到if语句对应的汇编语句

```txt
000D1083   .  E8 A2FFFFFF   call    000D102A
000D1088   .  85C0          test    eax, eax
000D108A   .  75 0A         jnz     short 000D1096
000D108C   .  FF15 14600D00 call    dword ptr [<&KERNEL32.IsDebugger>; [IsDebuggerPresent
000D1092   .  85C0          test    eax, eax
000D1094      74 23         je      short 000D10B9
000D1096   >  41            inc     ecx
000D1097   .  41            inc     ecx
000D1098   .  41            inc     ecx
000D1099   .  41            inc     ecx
000D109A      CC            int3
000D109B   .  8B55 F4       mov     edx, dword ptr [ebp-C]
000D109E   .  E8 5DFFFFFF   call    000D1000
000D10A3      EB 4A         jmp     short 000D10EF
```

关键就是对这些汇编语句进行修改来获得flag数据，运行过程中有一个int3断点应该是让程序进行终止的，然后就是je跳转语句和jmp跳转语句了。对je跳转语句进行修改和jmp跳转语句进行修改，设置断点进行调试应该就可以获得flag

修改过的汇编语句

```txt
000D1083   .  E8 A2FFFFFF   call    000D102A
000D1088   .  85C0          test    eax, eax
000D108A   .  75 0A         jnz     short 000D1096
000D108C   .  FF15 14600D00 call    dword ptr [<&KERNEL32.IsDebugger>; [IsDebuggerPresent
000D1092   .  85C0          test    eax, eax
000D1094      90            nop
000D1095      90            nop
000D1096   >  41            inc     ecx
000D1097   .  41            inc     ecx
000D1098   .  41            inc     ecx
000D1099   .  41            inc     ecx
000D109A      90            nop
000D109B   .  8B55 F4       mov     edx, dword ptr [ebp-C]
000D109E   .  E8 5DFFFFFF   call    000D1000
000D10A3      EB 14         jmp     short 000D10B9
```

然后设置断点进行调试，来获得flag

![image-20210913085300812](/images/XCTF-REVERSE-novice_writeup/image-20210913085300812.png)

成功得到flag

```txt
flag{reversing_is_not_that_hard!}
```



## 0xB maze

走迷宫的题目，逆向题目中多少有些趣味的题目，来一起走迷宫吧

首先查看一下程序信息

![image-20210913085802357](/images/XCTF-REVERSE-novice_writeup/image-20210913085802357.png)

64位的程序，使用x64 IDA pro查看一下

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v3; // rbx
  int v4; // eax
  char v5; // bp
  char v6; // al
  const char *v7; // rdi
  unsigned int v9; // [rsp+0h] [rbp-28h] BYREF
  int v10[9]; // [rsp+4h] [rbp-24h] BYREF

  v10[0] = 0;
  v9 = 0;
  puts("Input flag:");
  scanf("%s", &s1);
  if ( strlen(&s1) != 24 || strncmp(&s1, "nctf{", 5uLL) || *(&byte_6010BF + 24) != 125 )
  {
LABEL_22:
    puts("Wrong flag!");
    exit(-1);
  }
  v3 = 5LL;
  if ( strlen(&s1) - 1 > 5 )
  {
    while ( 1 )
    {
      v4 = *(&s1 + v3);
      v5 = 0;
      if ( v4 > 78 )
      {
        if ( (unsigned __int8)v4 == 79 )
        {
          v6 = sub_400650(v10);
          goto LABEL_14;
        }
        if ( (unsigned __int8)v4 == 111 )
        {
          v6 = sub_400660(v10);
          goto LABEL_14;
        }
      }
      else
      {
        if ( (unsigned __int8)v4 == 46 )
        {
          v6 = sub_400670(&v9);
          goto LABEL_14;
        }
        if ( (unsigned __int8)v4 == 48 )
        {
          v6 = sub_400680(&v9);
LABEL_14:
          v5 = v6;
          goto LABEL_15;
        }
      }
LABEL_15:
      if ( !(unsigned __int8)sub_400690(asc_601060, (unsigned int)v10[0], v9) )
        goto LABEL_22;
      if ( ++v3 >= strlen(&s1) - 1 )
      {
        if ( v5 )
          break;
LABEL_20:
        v7 = "Wrong flag!";
        goto LABEL_21;
      }
    }
  }
  if ( asc_601060[8 * v9 + v10[0]] != 35 )
    goto LABEL_20;
  v7 = "Congratulations!";
LABEL_21:
  puts(v7);
  return 0LL;
}
```

函数的主要逻辑应该是根据输入的值来进行走迷宫的，走出迷宫即得到flag。程序中肯定存在的有迷宫的地图作为静态数据存储。所以可以尝试查看静态数据：

![image-20210913091057871](/images/XCTF-REVERSE-novice_writeup/image-20210913091057871.png)

果然有一个类似迷宫的数据，查看迷宫数据

```txt
  *******   *  **** * ****  * ***  *#  *** *** ***     *********
```

需要对代码进行分析来进一步得到迷宫的大致样子

```c
if ( strlen(&s1) != 24 || strncmp(&s1, "nctf{", 5uLL) || *(&byte_6010BF + 24) != 125 )
  {
LABEL_22:
    puts("Wrong flag!");
    exit(-1);
  }
```

根据这段代码可以判断出走出迷宫需要18个操作数

```c
while ( 1 )
    {
      v4 = *(&s1 + v3);
      v5 = 0;
      if ( v4 > 78 )
      {
        if ( (unsigned __int8)v4 == 'O' )
        {
          v6 = sub_400650(v10);
          goto LABEL_14;
        }
        if ( (unsigned __int8)v4 == 'o' )
        {
          v6 = sub_400660(v10);
          goto LABEL_14;
        }
      }
      else
      {
        if ( (unsigned __int8)v4 == '.' )
        {
          v6 = sub_400670(&v9);
          goto LABEL_14;
        }
        if ( (unsigned __int8)v4 == '0' )
        {
          v6 = sub_400680(&v9);
```

这些是对迷宫操作的判断，根据这些判断可以确定我们如何进行迷宫的操作

首先根据反汇编的代码进行分析，可以发现有两个关键数据有着比较重要的作用就是`v10`就`v9`的数据，根据跟进分析，发现`v10` 是进行横向操作，发现`v9` 是纵向操作。然后根据函数内部的加或减来确定 上下左右 的方向。

对代码进行进一步分析应该就知道对应操作：

```txt
'O'  ←
'o'  →
'.'  ↑
'0'  ↓
```

根据代码的分析，迷宫应该是8x8的迷宫，可以排列出迷宫的样子

```txt
00******
*000*00*
***0*0**
**00*0**
*00*#00*
**0***0*
**00000*
********
```

根据目前的分析的结果就可以开心地走迷宫了：

```txt
o0oo00O000oooo..OO
```

迷宫路线即为flag，因此本题的flag为：

```txt
nctf{o0oo00O000oooo..OO}
```
