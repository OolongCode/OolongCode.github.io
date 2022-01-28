---
title: "XCTF REVERSE Expert [1~6] Writeup"
date: 2022-01-28T19:33:49+08:00
draft: false
math: false
tags: ["CTF"]
toc: true
---

# XCTF-REVERSE-高手区-[1-6] writeup

有段时间没有刷题了，刷刷题找找手感

## 0x0 answer_to_everything

使用DIE查看程序信息

![image-20211031104627471](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211031104627471.png)

程序没有壳，而且是64位。然后看看文件长什么样，静态分析的时刻来临：

![image-20211031104740182](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211031104740182.png)

发现关键函数，跟进这个函数

```c
__int64 __fastcall not_the_flag(int a1)
{
  if ( a1 == 42 )
    puts("Cipher from Bill \nSubmit without any tags\n#kdudpeh");
  else
    puts("YOUSUCK");
  return 0LL;
}
```

根据题目要求，应该是要对一个字段进行sha1加密，仔细观察逆向程序，发现应该是对`kdudpeh`进行sha1加密

使用python进行sha1加密得：

```txt
80ee2a3fe31da904c596d993f7f1de4827c1450a
```

故本题flag为

```txt
flag{80ee2a3fe31da904c596d993f7f1de4827c1450a}
```

## 0x1 elrond32

使用DIE查询一下文件信息

![image-20211031105318823](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211031105318823.png)

32位的exec文件，使用IDA pro打开

定位到main函数的位置

```c
int __cdecl main(int a1, char **a2)
{
  if ( a1 > 1 && sub_8048414(a2[1], 0) )
  {
    puts("Access granted");
    sub_8048538(a2[1]);
  }
  else
  {
    puts("Access denied");
  }
  return 0;
}
```

关键函数应该是在`sub_8048538(a2[1])`函数里面

跟进到`sub_8048538(a2[1])`函数

```c
int __cdecl sub_8048538(int a1)
{
  int v2[33]; // [esp+18h] [ebp-A0h] BYREF
  int i; // [esp+9Ch] [ebp-1Ch]

  qmemcpy(v2, &unk_8048760, sizeof(v2));
  for ( i = 0; i <= 32; ++i )
    putchar(v2[i] ^ *(char *)(a1 + i % 8));
  return putchar(10);
}
```

发现和参数a2有关联，需要寻找`a2`的相关线索

发现`if`判断那个位置的函数有对`a2`数据进行处理，跟进那个函数：

```c
int __cdecl sub_8048414(_BYTE *a1, int a2)
{
  int result; // eax

  switch ( a2 )
  {
    case 0:
      if ( *a1 == 105 )
        goto LABEL_19;
      result = 0;
      break;
    case 1:
      if ( *a1 == 101 )
        goto LABEL_19;
      result = 0;
      break;
    case 3:
      if ( *a1 == 110 )
        goto LABEL_19;
      result = 0;
      break;
    case 4:
      if ( *a1 == 100 )
        goto LABEL_19;
      result = 0;
      break;
    case 5:
      if ( *a1 == 97 )
        goto LABEL_19;
      result = 0;
      break;
    case 6:
      if ( *a1 == 103 )
        goto LABEL_19;
      result = 0;
      break;
    case 7:
      if ( *a1 == 115 )
        goto LABEL_19;
      result = 0;
      break;
    case 9:
      if ( *a1 == 114 )
LABEL_19:
        result = sub_8048414(a1 + 1, 7 * (a2 + 1) % 11);
      else
        result = 0;
      break;
    default:
      result = 1;
      break;
  }
  return result;
}
```

对于`a2`进行递归变化，结合对于`a2`处理的函数，可以编写个小程序来生成flag

```c++
#include <iostream>

int main()
{
  int v2[]
  {
    0x0F, 0x1F,  0x04, 0x09, 0x1C, 0x12,  0x42,  0x09,  0x0C, 0x44, 
    0x0D, 0x07,  0x09, 0x06, 0x2D, 0x37,  0x59,  0x1E,  0x00, 0x59, 
    0x0F, 0x08,  0x1C, 0x23, 0x36, 0x07,  0x55,  0x02,  0x0C, 0x08, 
    0x41, 0x0A,  0x14
  };
  int key[]
  {
    105,115,101,110,103,97,114,100
  };
  for(int i = 0;i<33;i++)
  {
    putchar(v2[i]^key[i%8]);
  }
  return 0;
}
```

编译并运行，就能得到flag

```txt
flag{s0me7hing_S0me7hinG_t0lki3n}
```



## 0x2 666

使用DIE查询一下程序信息：

![image-20211031153424353](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211031153424353.png)

64位程序，使用GCC进行编译的无壳程序

使用IDA x64 pro 对程序进行静态分析：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[240]; // [rsp+0h] [rbp-1E0h] BYREF
  char v5[240]; // [rsp+F0h] [rbp-F0h] BYREF

  memset(s, 0, 30uLL);
  printf("Please Input Key: ");
  __isoc99_scanf("%s", v5);
  encode(v5, (__int64)s);
  if ( strlen(v5) == key )
  {
    if ( !strcmp(s, enflag) )
      puts("You are Right");
    else
      puts("flag{This_1s_f4cker_flag}");
  }
  return 0;
}
```

关键函数应该是在encode里面，这个程序的基本逻辑就是将输入进行`encode`函数处理，然后与指定的字符串进行比对来进行验证。

而输入的字符串就是flag数据。

因此，这道题目也就可以非常简单进行处理，也就是对`encode`函数进行逆向处理就可

首先，还是查看一下`encode`的内部实现情况：

```c
int __fastcall encode(const char *a1, __int64 a2)
{
  char v3[104]; // [rsp+10h] [rbp-70h]
  int v4; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  i = 0;
  v4 = 0;
  if ( strlen(a1) != key )
    return puts("Your Length is Wrong");
  for ( i = 0; i < key; i += 3 )
  {
    v3[i + 64] = key ^ (a1[i] + 6);
    v3[i + 33] = (a1[i + 1] - 6) ^ key;
    v3[i + 2] = a1[i + 2] ^ 6 ^ key;
    *(_BYTE *)(a2 + i) = v3[i + 64];
    *(_BYTE *)(a2 + i + 1LL) = v3[i + 33];
    *(_BYTE *)(a2 + i + 2LL) = v3[i + 2];
  }
  return a2;
}
```

进行跟踪发现`key = 18`

可以得知我们输入的内容长度为18

根据编码函数编写一个解密器进行程序破解

```c++
#include <iostream>

int main()
{
  int enflag[] =
  {
    0x69, 0x7A, 0x77, 0x68, 0x72, 0x6F, 0x7A, 0x22, 0x22, 0x77, 
    0x22, 0x76, 0x2E, 0x4B, 0x22, 0x2E, 0x4E, 0x69, 0x00
  };
  int key = 0x12;
  int i = 0;
  for(i;i<key;i+=3)
  {
    putchar((key^enflag[i])-6);
    putchar((enflag[i+1]^key)+6);
    putchar((enflag[i+2]^key^6));
  }
  return 0;
}
```

编译并运行程序就能拿到flag：

```txt
unctf{b66_6b6_66b}
```



## 0x3 IgniteMe

首先是使用DIE进行程序信息的查看：

![image-20211031161028282](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211031161028282.png)

32位的PE程序，PE程序可以使用的工具就有很多了，首先还是静态分析：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  size_t i; // [esp+4Ch] [ebp-8Ch]
  char v5[8]; // [esp+50h] [ebp-88h] BYREF
  char Str[128]; // [esp+58h] [ebp-80h] BYREF

  sub_402B30(&unk_446360, "Give me your flag:");
  sub_4013F0(sub_403670);
  sub_401440(Str, 127);
  if ( strlen(Str) < 0x1E && strlen(Str) > 4 )
  {
    strcpy(v5, "EIS{");
    for ( i = 0; i < strlen(v5); ++i )
    {
      if ( Str[i] != v5[i] )
        goto LABEL_7;
    }
    if ( Str[28] != 125 )
    {
LABEL_7:
      sub_402B30(&unk_446360, "Sorry, keep trying! ");
      sub_4013F0(sub_403670);
      return 0;
    }
    if ( (unsigned __int8)sub_4011C0(Str) )
      sub_402B30(&unk_446360, "Congratulations! ");
    else
      sub_402B30(&unk_446360, "Sorry, keep trying! ");
    sub_4013F0(sub_403670);
    result = 0;
  }
  else
  {
    sub_402B30(&unk_446360, "Sorry, keep trying!");
    sub_4013F0(sub_403670);
    result = 0;
  }
  return result;
}
```

找到关键加密的位置进行分析

即对函数`sub_4011c0(str)`进行分析

```c
bool __cdecl sub_4011C0(char *Str)
{
  size_t v2; // eax
  int v3; // [esp+50h] [ebp-B0h]
  char Str2[32]; // [esp+54h] [ebp-ACh] BYREF
  int v5; // [esp+74h] [ebp-8Ch]
  int v6; // [esp+78h] [ebp-88h]
  size_t i; // [esp+7Ch] [ebp-84h]
  char v8[128]; // [esp+80h] [ebp-80h] BYREF

  if ( strlen(Str) <= 4 )
    return 0;
  i = 4;
  v6 = 0;
  while ( i < strlen(Str) - 1 )
    v8[v6++] = Str[i++];
  v8[v6] = 0;
  v5 = 0;
  v3 = 0;
  memset(Str2, 0, sizeof(Str2));
  for ( i = 0; ; ++i )
  {
    v2 = strlen(v8);
    if ( i >= v2 )
      break;
    if ( v8[i] >= 97 && v8[i] <= 122 )
    {
      v8[i] -= 32;
      v3 = 1;
    }
    if ( !v3 && v8[i] >= 65 && v8[i] <= 90 )
      v8[i] += 32;
    Str2[i] = byte_4420B0[i] ^ sub_4013C0(v8[i]);
    v3 = 0;
  }
  return strcmp("GONDPHyGjPEKruv{{pj]X@rF", Str2) == 0;
}
```

直接就是一个加密算法，直接进行手撸一个解密算法即可：

```c++
#include <iostream>
#include <cstring>

int main()
{
  char flag[128]{ 0 };
  char s[]{
  0x0D, 0x13, 0x17, 0x11, 0x02, 0x01, 0x20, 0x1D, 0x0C, 0x02, 
  0x19, 0x2F, 0x17, 0x2B, 0x24, 0x1F, 0x1E, 0x16, 0x09, 0x0F, 
  0x15, 0x27, 0x13, 0x26, 0x0A, 0x2F, 0x1E, 0x1A, 0x2D, 0x0C, 
  0x22, 0x04
  };
  char Str[]{ "GONDPHyGjPEKruv{{pj]X@rF" };
  for(int i{ 0 };i<strlen(Str);i++)
  {
    flag[i] = ((Str[i]^s[i])-72)^0x55;
    if(flag[i] >= 'a' && flag[i] <= 'z')
    {
      flag[i] -= 32;
    }
    else if(flag[i] >= 'A' && flag[i] <= 'Z')
    {
      flag[i] += 32;
    }
  }
  std::cout << "EIS{" << flag << "}" << std::endl;
  return 0;
}

```

编译并运行，就可以得到flag

```txt
EIS{wadx_tdgk_aihc_ihkn_pjlm}
```



## 0x4 debug

使用DIE进行正常的程序信息查询：

![image-20211101080738116](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211101080738116.png)

.Net编译的程序，看样子不太友好。面对从未见到过的程序，该怎么做呢？这种情况下，就要使用强大的搜索引擎来寻找答案，经过搜索引擎的帮助，我这边找到了一个工具可以进行.Net程序的逆向——dnSpy

使用dnSpy来进行.Net程序的开心逆向吧！

![image-20211101082430169](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211101082430169.png)

dnSpy程序载入页面，dnSpy是一个非常好用的.Net程序和C#程序逆向工具，而且dnSpy的操作方式与Visual Studio非常相似，可以根据Visual Studio的操作模式进行debug。

首先，需要寻找到关键函数和关键代码位置

![image-20211101082804148](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211101082804148.png)

经过一番寻找，发现在02000003的位置有存在关键代码，根据关键代码跟进关键函数发现：

![image-20211101083006881](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211101083006881.png)

flag就存在在这里，使用断点断在入口函数这里来进行调试，得到：

![image-20211101083207311](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211101083207311.png)

得到flag：

```txt
flag{967DDDFBCD32C1F53527C221D9E40A0B}
```



## 0x5 Guess-the-Number

题目直接给了一个jar程序文件，应该是一个java逆向题目，java逆向和Android逆向类似，故可以使用相似的工具进行反编译：

```java
package defpackage;

import java.math.BigInteger;

/* renamed from: guess  reason: default package */
public class guess {
    static String XOR(String _str_one, String _str_two) {
        return new BigInteger(_str_one, 16).xor(new BigInteger(_str_two, 16)).toString(16);
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            try {
                if (309137378 == Integer.parseInt(args[0])) {
                    int my_num = 349763335 + 345736730;
                    System.out.println("your flag is: " + XOR("4b64ca12ace755516c178f72d05d7061", "ecd44646cfe5994ebeb35bf922e25dba"));
                    return;
                }
                System.err.println("wrong guess!");
                System.exit(1);
            } catch (NumberFormatException e) {
                System.err.println("please enter an integer \nexample: java -jar guess 12");
                System.exit(1);
            }
        } else {
            System.err.println("wrong guess!");
            int num = 1000000 + 1;
            System.exit(1);
        }
    }
}
```

可以直接拖到idea进行参数调试来得到flag:cat:（偷懒小技巧）

![image-20211101084458531](/images/XCTF-REVERSE-expert-[1-6]_writeup/image-20211101084458531.png)

成功得到flag：

```txt
a7b08c546302cc1fd2a4d48bf2bf2ddb
```



