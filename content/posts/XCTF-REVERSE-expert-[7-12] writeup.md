---
title: "XCTF REVERSE Expert [7~12] Writeup"
date: 2022-01-28T19:33:59+08:00
draft: false
math: false
tags: ["ctf","writeup"]
toc: true
---

# XCTF-REVERSE-高手区-[7-12] writeup

感觉攻防世界的逆向题目还是蛮有意思的，刷着玩玩，就当作闯关游戏一样！

## 0x0 EasyRE

使用DIE查看一下程序信息：

![image-20211101090530961](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211101090530961.png)

无壳32位程序，直接静态分析走起！

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // kr00_4
  int v4; // edx
  char *v5; // esi
  char v6; // al
  unsigned int i; // edx
  int v8; // eax
  char Arglist[16]; // [esp+2h] [ebp-24h] BYREF
  __int64 v11; // [esp+12h] [ebp-14h] BYREF
  int v12; // [esp+1Ah] [ebp-Ch]
  __int16 v13; // [esp+1Eh] [ebp-8h]

  sub_401020(Format, Arglist[0]);
  v12 = 0;
  v13 = 0;
  *(_OWORD *)Arglist = 0i64;
  v11 = 0i64;
  sub_401050("%s", (char)Arglist);
  v3 = strlen(Arglist);
  if ( v3 >= 0x10 && v3 == 24 )
  {
    v4 = 0;
    v5 = (char *)&v11 + 7;
    do
    {
      v6 = *v5--;
      byte_40336C[v4++] = v6;
    }
    while ( v4 < 24 );
    for ( i = 0; i < 0x18; ++i )
      byte_40336C[i] = (byte_40336C[i] + 1) ^ 6;
    v8 = strcmp(byte_40336C, aXircjR2twsv3pt);
    if ( v8 )
      v8 = v8 < 0 ? -1 : 1;
    if ( !v8 )
    {
      sub_401020("right\n", Arglist[0]);
      system("pause");
    }
  }
  return 0;
}
```

看代码，应该是比较简单的。但是需要对代码进行相对比较仔细的审计，来确保代码审计的成功

首先程序先对数组进行了倒序处理

```c
v4 = 0;
v5 = (char *)&v11 + 7;
do
{
  v6 = *v5--;
  byte_40336C[v4++] = v6;
}
while ( v4 < 24 );
```

然后是对数据进行处理

```c
for ( i = 0; i < 0x18; ++i )
  byte_40336C[i] = (byte_40336C[i] + 1) ^ 6;
```

而我们的目标是得到原始匹配的输入数据来获取到flag

编写一个小程序来获得flag

```c++
#include <iostream>
#include <cstring>

int main()
{
  int data[]{
    0x78, 0x49, 0x72, 0x43, 0x6A, 0x7E, 0x3C, 0x72, 0x7C, 0x32, 
    0x74, 0x57, 0x73, 0x76, 0x33, 0x50, 0x74, 0x49, 0x7F, 0x7A, 
    0x6E, 0x64, 0x6B, 0x61
  };
  for(int i{ 0 };i<24;i++)
  {
    data[i] = (data[i]^6)-1;
  }
  for(int j{23};j>=0;j--)
  {
    putchar(data[j]);
  }
  return 0;
}
```

编译并运行程序得到：

```txt
flag{xNqU4otPq3ys9wkDsN} 
```



## 0x1 Shuffle

丢到DIE探测一波：

![image-20211101161009642](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211101161009642.png)

没有壳，32位的Ubuntu编译的程序，直接静态分析

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  time_t v3; // ebx
  __pid_t v4; // eax
  int i; // [esp+14h] [ebp-44h]
  unsigned int v7; // [esp+18h] [ebp-40h]
  unsigned int v8; // [esp+1Ch] [ebp-3Ch]
  char v9; // [esp+20h] [ebp-38h]
  char s[40]; // [esp+24h] [ebp-34h] BYREF
  unsigned int v11; // [esp+4Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  strcpy(s, "SECCON{Welcome to the SECCON 2014 CTF!}");
  v3 = time(0);
  v4 = getpid();
  srand(v3 + v4);
  for ( i = 0; i <= 99; ++i )
  {
    v7 = rand() % 0x28u;
    v8 = rand() % 0x28u;
    v9 = s[v7];
    s[v7] = s[v8];
    s[v8] = v9;
  }
  puts(s);
  return 0;
}
```

由于题目描述：

```txt
找到字符串在随机化之前
```

故flag为：

```txt
SECCON{Welcome to the SECCON 2014 CTF!}
```



## 0x2 re-for-50-plz-50

使用DIE查看程序信息：

![image-20211102081907475](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102081907475.png)

没有壳32位程序，直接静态分析：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int i; // [sp+18h] [+18h]

  for ( i = 0; i < 31; ++i )
  {
    if ( meow[i] != (char)(argv[1][i] ^ 0x37) )
    {
      print("NOOOOOOOOOOOOOOOOOO\n");
      exit_funct();
    }
  }
  puts("C0ngr4ssulations!! U did it.", argv, envp);
  exit_funct();
}
```

代码非常简单，就是对程序静态字符串进行按位异或操作，编写一个程序来求解：

```c++
#include <iostream>

int main()
{
  int meow[]{
    0x63, 0x62, 0x74, 0x63, 0x71, 0x4C, 0x55, 0x42, 0x43, 0x68, 
    0x45, 0x52, 0x56, 0x5B, 0x5B, 0x4E, 0x68, 0x40, 0x5F, 0x58, 
    0x5E, 0x44, 0x5D, 0x58, 0x5F, 0x59, 0x50, 0x56, 0x5B, 0x43, 
    0x4A
  };
  int f{0x37};
  for(int i{0};i<31;i++)
  {
    putchar(meow[i]^f);
  }
  return 0;
}
```

编译并运行得到：

```txt
TUCTF{but_really_whoisjohngalt}
```



## 0x3 dmd-50

使用DIE来进行探测：

![image-20211102130922964](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102130922964.png)

64位ELF程序，静态分析一探究竟：

![image-20211102135037235](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102135037235.png)

看样子应该是C++编写的程序，可以发现汇编代码有个`md5`的函数，应该是使用了md5加密

后面的汇编语句进行了一系列的比较操作：

```assembly
0x00400f36      cmp     al, 0x37   ; 55
0x00400f38      jne     0x40129b
0x00400f3e      mov     rax, qword [var_58h]
0x00400f42      add     rax, 1
0x00400f46      movzx   eax, byte [rax]
0x00400f49      cmp     al, 0x38   ; 56
0x00400f4b      jne     0x40129b
0x00400f51      mov     rax, qword [var_58h]
0x00400f55      add     rax, 2
0x00400f59      movzx   eax, byte [rax]
0x00400f5c      cmp     al, 0x30   ; 48
0x00400f5e      jne     0x40129b
0x00400f64      mov     rax, qword [var_58h]
0x00400f68      add     rax, 3
0x00400f6c      movzx   eax, byte [rax]
0x00400f6f      cmp     al, 0x34   ; 52
0x00400f71      jne     0x40129b
0x00400f77      mov     rax, qword [var_58h]
0x00400f7b      add     rax, 4
0x00400f7f      movzx   eax, byte [rax]
0x00400f82      cmp     al, 0x33   ; 51
0x00400f84      jne     0x40129b
0x00400f8a      mov     rax, qword [var_58h]
0x00400f8e      add     rax, 5
0x00400f92      movzx   eax, byte [rax]
0x00400f95      cmp     al, 0x38   ; 56
0x00400f97      jne     0x40129b
0x00400f9d      mov     rax, qword [var_58h]
0x00400fa1      add     rax, 6
0x00400fa5      movzx   eax, byte [rax]
0x00400fa8      cmp     al, 0x64   ; 100
0x00400faa      jne     0x40129b
0x00400fb0      mov     rax, qword [var_58h]
0x00400fb4      add     rax, 7
0x00400fb8      movzx   eax, byte [rax]
0x00400fbb      cmp     al, 0x35   ; 53
0x00400fbd      jne     0x40129b
0x00400fc3      mov     rax, qword [var_58h]
0x00400fc7      add     rax, 8
0x00400fcb      movzx   eax, byte [rax]
0x00400fce      cmp     al, 0x62   ; 98
0x00400fd0      jne     0x40129b
0x00400fd6      mov     rax, qword [var_58h]
0x00400fda      add     rax, 9
0x00400fde      movzx   eax, byte [rax]
0x00400fe1      cmp     al, 0x36   ; 54
0x00400fe3      jne     0x40129b
0x00400fe9      mov     rax, qword [var_58h]
0x00400fed      add     rax, 0xa
0x00400ff1      movzx   eax, byte [rax]
0x00400ff4      cmp     al, 0x65   ; 101
0x00400ff6      jne     0x40129b
0x00400ffc      mov     rax, qword [var_58h]
0x00401000      add     rax, 0xb   ; 11
0x00401004      movzx   eax, byte [rax]
0x00401007      cmp     al, 0x32   ; 50
0x00401009      jne     0x40129b
0x0040100f      mov     rax, qword [var_58h]
0x00401013      add     rax, 0xc   ; 12
0x00401017      movzx   eax, byte [rax]
0x0040101a      cmp     al, 0x39   ; 57
0x0040101c      jne     0x40129b
0x00401022      mov     rax, qword [var_58h]
0x00401026      add     rax, 0xd   ; 13
0x0040102a      movzx   eax, byte [rax]
0x0040102d      cmp     al, 0x64   ; 100
0x0040102f      jne     0x40129b
0x00401035      mov     rax, qword [var_58h]
0x00401039      add     rax, 0xe   ; 14
0x0040103d      movzx   eax, byte [rax]
0x00401040      cmp     al, 0x62   ; 98
0x00401042      jne     0x40129b
0x00401048      mov     rax, qword [var_58h]
0x0040104c      add     rax, 0xf   ; 15
0x00401050      movzx   eax, byte [rax]
0x00401053      cmp     al, 0x30   ; 48
0x00401055      jne     0x40129b
0x0040105b      mov     rax, qword [var_58h]
0x0040105f      add     rax, 0x10  ; 16
0x00401063      movzx   eax, byte [rax]
0x00401066      cmp     al, 0x38   ; 56
0x00401068      jne     0x40129b
0x0040106e      mov     rax, qword [var_58h]
0x00401072      add     rax, 0x11  ; 17
0x00401076      movzx   eax, byte [rax]
0x00401079      cmp     al, 0x39   ; 57
0x0040107b      jne     0x40129b
0x00401081      mov     rax, qword [var_58h]
0x00401085      add     rax, 0x12  ; 18
0x00401089      movzx   eax, byte [rax]
0x0040108c      cmp     al, 0x38   ; 56
0x0040108e      jne     0x40129b
0x00401094      mov     rax, qword [var_58h]
0x00401098      add     rax, 0x13  ; 19
0x0040109c      movzx   eax, byte [rax]
0x0040109f      cmp     al, 0x62   ; 98
0x004010a1      jne     0x40129b
0x004010a7      mov     rax, qword [var_58h]
0x004010ab      add     rax, 0x14  ; 20
0x004010af      movzx   eax, byte [rax]
0x004010b2      cmp     al, 0x63   ; 99
0x004010b4      jne     0x40129b
0x004010ba      mov     rax, qword [var_58h]
0x004010be      add     rax, 0x15  ; 21
0x004010c2      movzx   eax, byte [rax]
0x004010c5      cmp     al, 0x34   ; 52
0x004010c7      jne     0x40129b
0x004010cd      mov     rax, qword [var_58h]
0x004010d1      add     rax, 0x16  ; 22
0x004010d5      movzx   eax, byte [rax]
0x004010d8      cmp     al, 0x66   ; 102
0x004010da      jne     0x40129b
0x004010e0      mov     rax, qword [var_58h]
0x004010e4      add     rax, 0x17  ; 23
0x004010e8      movzx   eax, byte [rax]
0x004010eb      cmp     al, 0x30   ; 48
0x004010ed      jne     0x40129b
0x004010f3      mov     rax, qword [var_58h]
0x004010f7      add     rax, 0x18  ; 24
0x004010fb      movzx   eax, byte [rax]
0x004010fe      cmp     al, 0x32   ; 50
0x00401100      jne     0x40129b
0x00401106      mov     rax, qword [var_58h]
0x0040110a      add     rax, 0x19  ; 25
0x0040110e      movzx   eax, byte [rax]
0x00401111      cmp     al, 0x32   ; 50
0x00401113      jne     0x40129b
0x00401119      mov     rax, qword [var_58h]
0x0040111d      add     rax, 0x1a  ; 26
0x00401121      movzx   eax, byte [rax]
0x00401124      cmp     al, 0x35   ; 53
0x00401126      jne     0x40129b
0x0040112c      mov     rax, qword [var_58h]
0x00401130      add     rax, 0x1b  ; 27
0x00401134      movzx   eax, byte [rax]
0x00401137      cmp     al, 0x39   ; 57
0x00401139      jne     0x40129b
0x0040113f      mov     rax, qword [var_58h]
0x00401143      add     rax, 0x1c  ; 28
0x00401147      movzx   eax, byte [rax]
0x0040114a      cmp     al, 0x33   ; 51
0x0040114c      jne     0x40129b
0x00401152      mov     rax, qword [var_58h]
0x00401156      add     rax, 0x1d  ; 29
0x0040115a      movzx   eax, byte [rax]
0x0040115d      cmp     al, 0x35   ; 53
0x0040115f      jne     0x40129b
0x00401165      mov     rax, qword [var_58h]
0x00401169      add     rax, 0x1e  ; 30
0x0040116d      movzx   eax, byte [rax]
0x00401170      cmp     al, 0x63   ; 99
0x00401172      jne     0x40129b
0x00401178      mov     rax, qword [var_58h]
0x0040117c      add     rax, 0x1f  ; 31
0x00401180      movzx   eax, byte [rax]
0x00401183      cmp     al, 0x30   ; 48
0x00401185      jne     0x40129b
```

根据汇编语句可以得到md5的字符应该是：

```txt
780438d5b6e29db0898bc4f0225935c0
```

试试使用一些md5破解的工具进行破解：

```txt
b781cbb29054db12f88f08c6e161c199
```

这个应该就是flag了，题目思路也就很简单。可能感到困难的是C++的反汇编。

本题flag：

```txt
b781cbb29054db12f88f08c6e161c199
```



## 0x4 parallel-comparator-200

题目直接给到了C的源代码

```c
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define FLAG_LEN 20

void * checking(void *arg) {
    char *result = malloc(sizeof(char));
    char *argument = (char *)arg;
    *result = (argument[0]+argument[1]) ^ argument[2];
    return result;
}

int highly_optimized_parallel_comparsion(char *user_string)
{
    int initialization_number;
    int i;
    char generated_string[FLAG_LEN + 1];
    generated_string[FLAG_LEN] = '\0';

    while ((initialization_number = random()) >= 64);
    
    int first_letter;
    first_letter = (initialization_number % 26) + 97;

    pthread_t thread[FLAG_LEN];
    char differences[FLAG_LEN] = {0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7};
    char *arguments[20];
    for (i = 0; i < FLAG_LEN; i++) {
        arguments[i] = (char *)malloc(3*sizeof(char));
        arguments[i][0] = first_letter;
        arguments[i][1] = differences[i];
        arguments[i][2] = user_string[i];

        pthread_create((pthread_t*)(thread+i), NULL, checking, arguments[i]);
    }

    void *result;
    int just_a_string[FLAG_LEN] = {115, 116, 114, 97, 110, 103, 101, 95, 115, 116, 114, 105, 110, 103, 95, 105, 116, 95, 105, 115};
    for (i = 0; i < FLAG_LEN; i++) {
        pthread_join(*(thread+i), &result);
        generated_string[i] = *(char *)result + just_a_string[i];
        free(result);
        free(arguments[i]);
    }

    int is_ok = 1;
    for (i = 0; i < FLAG_LEN; i++) {
        if (generated_string[i] != just_a_string[i])
            return 0;
    }

    return 1;
}

int main()
{
    char *user_string = (char *)calloc(FLAG_LEN+1, sizeof(char));
    fgets(user_string, FLAG_LEN+1, stdin);
    int is_ok = highly_optimized_parallel_comparsion(user_string);
    if (is_ok)
        printf("You win!\n");
    else
        printf("Wrong!\n");
    return 0;
}
```

应该是一个代码审计的题目，对C语言源码进行审计

找到关键函数代码：

```c
pthread_t thread[FLAG_LEN];
char differences[FLAG_LEN] = {0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7};
char *arguments[20];
for (i = 0; i < FLAG_LEN; i++) {
    arguments[i] = (char *)malloc(3*sizeof(char));
    arguments[i][0] = first_letter;
    arguments[i][1] = differences[i];
    arguments[i][2] = user_string[i];

    pthread_create((pthread_t*)(thread+i), NULL, checking, arguments[i]);
}
```

关键应该是`pthread_create`函数和`checking`函数

```c
void * checking(void *arg) {
    char *result = malloc(sizeof(char));
    char *argument = (char *)arg;
    *result = (argument[0]+argument[1]) ^ argument[2];
    return result;
}
```

通过对函数`pthread_create`的查阅并根据`checking`的返回值可以得到：

`result == 0` ，也就是可以得到一个等式关系来进行求解：

```c
(argument[0]+argument[1]) == argument[2];
```

故现在只需要得到`argument[0]`的数值就可以进行求解了：

```c
int first_letter;
first_letter = (initialization_number % 26) + 97;
```

现在可以知道`argument[0]`的取值范围在 0 \~ 25根据这个范围进行爆破。

根据上述分析，写一个python脚本求解：

```python
differences = [0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7]
for i in range(97,97+26):
    flag =""
    for k in differences:
        flag += chr(k+i)
    print(flag)
```

运行代码在输出结果中可以找到：

![image-20211102180423890](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102180423890.png)

故本题的flag:

```txt
lucky_hacker_you_are
```



## 0x5 secret-galaxy-300

使用DIE来对程序进行探测：

![image-20211102184409728](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102184409728.png)

没有壳，静态分析看下代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __main();
  fill_starbase(&starbase);
  print_starbase(&starbase);
  return 0;
}
```

分别跟进两个函数来查看

 fill_starbase：

```c
void __cdecl fill_starbase(int a1)
{
  int i; // [esp+8h] [ebp-10h]
  int v2; // [esp+Ch] [ebp-Ch]

  v2 = 0;
  for ( i = 0; i <= 4; ++i )
  {
    *(_DWORD *)(a1 + 24 * i) = galaxy_name[i];
    *(_DWORD *)(24 * i + a1 + 4) = rand();
    *(_DWORD *)(24 * i + a1 + 8) = 0;
    *(_DWORD *)(24 * i + a1 + 12) = 0;
    *(_DWORD *)(24 * i + a1 + 16) = 24 * (i + 1) + a1;
    *(_DWORD *)(a1 + 24 * i + 20) = v2;
    v2 = 24 * i + a1;
  }
```



print_starbase：

```c
int __cdecl print_starbase(int a1)
{
  int result; // eax
  const char *v2; // edx
  int i; // [esp+1Ch] [ebp-Ch]

  puts("--------------GALAXY DATABASE-------------");
  printf("%10s | %s | %s\n", "Galaxy name", "Existence of life", "Distance from Earth");
  result = puts("-------------------------------------------");
  for ( i = 0; i <= 4; ++i )
  {
    if ( *(_DWORD *)(24 * i + a1 + 8) == 1 )
      v2 = "INHABITED";
    else
      v2 = "IS NOT INHABITED";
    result = printf("%11s | %17s | %d\n", *(const char **)(24 * i + a1), v2, *(_DWORD *)(24 * i + a1 + 4));
  }
  return result;
}
```

实在是看不出什么线索，查看一下字符串输出

![image-20211102191117327](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102191117327.png)

发现有个字符串没有进行输出，有点可疑，跟进去一探究竟

![image-20211102191250757](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102191250757.png)

果然有些端倪，继续追踪

![image-20211102191341004](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102191341004.png)

再接再励，真相就在眼前

![image-20211102191448118](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102191448118.png)

这个字符串的地址是0x4013E0，拿到了地址就可以做很多事情了，可以使用Ollydbg跟踪到这个地址来进行动态分析，如果没有问题的话，flag应该就在动态调试的内存中。先来尝试一下调试调试：

步入到断点0x4013E0，不断进行F8单步运行，运行到函数结尾位置，查看一下内存：

![image-20211102192916295](/images/XCTF-REVERSE-expert-[7-12]_writeup/image-20211102192916295.png)

发现可疑字符，这段字符应该就是可能的flag

这道题目的flag是

```txt
aliens_are_around_us
```

---
