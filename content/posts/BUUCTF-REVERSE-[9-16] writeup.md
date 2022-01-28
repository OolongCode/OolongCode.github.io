---
title: "BUUCTF REVERSE [9~16] Writeup"
date: 2022-01-28T19:18:38+08:00
draft: false
math: false
tags: ["ctf","writeup"]
toc: true
---

# BUUCTF-REVERSE-\[9-16\] writeup

8道逆向工程的小题目，re真是越来越有意思了

![image-20210808095050806](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210808095050806.png)

## 0x0 不一样的flag

简单看看题目描述

```txt
是不是做习惯了常规的逆向题目？试试这道题，看你在能不能在程序中找到真正的flag！注意：flag并非是flag{XXX}形式，就是一个’字符串‘，考验眼力的时候到了！ 注意：得到的 flag 请包上 flag{} 提交
```

应该会是一道非常有趣的题目，非常有意思的题目。

首先还是先查询一下程序信息

![image-20210808211004969](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210808211004969.png)

没有壳，是一个32位的PE程序，丢进Cutter里面看个究竟吧

```c
#include <stdint.h>
 
int32_t dbg_main (void) {
    int32_t var_4h;
    char[5][5] a;
    int[2] location;
    int32_t var_34h;
    int32_t choice;
    int32_t i;
    int32_t var_40h;
    /* int main(); */
    _main (ebx, esi, edi);
    location = 0;
    var_34h = 0;
    edx = &a;
    ebx = "*11110100001010000101111#";
    eax = 0x19;
    edi = edx;
    esi = ebx;
    ecx = eax;
    do {
        *(es:edi) = *(esi);
        ecx--;
        esi++;
        es:edi++;
    } while (ecx != 0);
    goto label_1;
label_0:
label_1:
    _puts ("you can choose one action to execute");
    _puts ("1 up");
    _puts ("2 down");
    _puts ("3 left");
    _printf ("4 right\n:");
    eax = &choice;
    _scanf (0x403066, eax);
    eax = choice;
    if (eax != 2) {
        if (eax <= 2) {
            if (eax != 1) {
            } else {
                if (eax != 3) {
                    if (eax == 4) {
                        goto label_2;
                    }
                    eax = location;
                    eax--;
                    location = eax;
                } else {
                } else {
                    eax = location;
                    eax++;
                    location = eax;
                    goto label_3;
                }
            }
            eax = var_34h;
            eax--;
            var_34h = eax;
            goto label_3;
label_2:
            eax = var_34h;
            eax++;
            var_34h = eax;
            goto label_3;
        }
        _exit (1);
    }
label_3:
    i = 0;
    while (i <= 1) {
        eax = i;
        eax = *((esp + eax*4 + 0x30));
        if (eax >= 0) {
            eax = i;
            eax = *((esp + eax*4 + 0x30));
            if (eax <= 4) {
                goto label_4;
            }
        }
        _exit (1);
label_4:
        i++;
    }
    edx = location;
    ecx = var_34h;
    eax = edx;
    eax <<= 2;
    eax += edx;
    edx = &var_40h;
    eax += edx;
    eax += ecx;
    eax -= 0x29;
    al = *(eax);
    if (al == 0x31) {
        _exit (1);
    }
    edx = location;
    ecx = var_34h;
    eax = edx;
    eax <<= 2;
    eax += edx;
    esi = &var_40h;
    eax += esi;
    eax += ecx;
    eax -= 0x29;
    al = *(eax);
    if (al != 0x23) {
        goto label_0;
    }
    _puts ("\nok, the order you enter is the flag!");
    _exit (0);
}
```

根据反编译的代码，可以发现这道题目是一个走迷宫的题目，总体而言，还是挺有意思的，找到迷宫数据然后走出迷宫。

根据迷宫的特性，需要寻找一下一些关键性的信息，来完成迷宫的

首先是迷宫的信息，可以从反编译的关键代码找到迷宫信息

```c
 ebx = "*11110100001010000101111#";
```

将数据整合一下便得到如下内容：

```txt
*1111
01000
01010
00010
1111#
```

对于这个数据可以非常清晰看出迷宫的形式，*是起点，#是终点，1不能通行，0可以通行。

然后是寻找操作指令，自然也可以从反编译代码中找到

```c
_puts ("you can choose one action to execute");
    _puts ("1 up");
    _puts ("2 down");
    _puts ("3 left");
    _printf ("4 right\n:");
```

根据迷宫和操作数，就可以得到flag

```txt
flag{222441144222}
```



## 0x1 SimpleRev

首先查一下程序信息，看看程序具体是个什么

![image-20210809170725758](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210809170725758.png)

是一个Linux程序，使用x64 IDA pro进行打开

找到main函数位置，查看反编译代码

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char v4; // [rsp+Fh] [rbp-1h]

  while ( 1 )
  {
    while ( 1 )
    {
      printf("Welcome to CTF game!\nPlease input d/D to start or input q/Q to quit this program: ");
      v4 = getchar();
      if ( v4 != 100 && v4 != 68 )
        break;
      Decry("Welcome to CTF game!\nPlease input d/D to start or input q/Q to quit this program: ", argv);
    }
    if ( v4 == 113 || v4 == 81 )
      Exit("Welcome to CTF game!\nPlease input d/D to start or input q/Q to quit this program: ", argv);
    puts("Input fault format!");
    v3 = getchar();
    putchar(v3);
  }
}
```

对反编译的代码进行简单的审计，发现Decry函数是关键函数，可以看看这个函数的具体实现细节

```c
unsigned __int64 Decry()
{
  char v1; // [rsp+Fh] [rbp-51h]
  int v2; // [rsp+10h] [rbp-50h]
  int v3; // [rsp+14h] [rbp-4Ch]
  int i; // [rsp+18h] [rbp-48h]
  int v5; // [rsp+1Ch] [rbp-44h]
  char src[8]; // [rsp+20h] [rbp-40h] BYREF
  __int64 v7; // [rsp+28h] [rbp-38h]
  int v8; // [rsp+30h] [rbp-30h]
  __int64 v9[2]; // [rsp+40h] [rbp-20h] BYREF
  int v10; // [rsp+50h] [rbp-10h]
  unsigned __int64 v11; // [rsp+58h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  *(_QWORD *)src = 0x534C43444ELL;
  v7 = 0LL;
  v8 = 0;
  v9[0] = 0x776F646168LL;
  v9[1] = 0LL;
  v10 = 0;
  text = (char *)join(key3, v9);
  strcpy(key, key1);
  strcat(key, src);
  v2 = 0;
  v3 = 0;
  getchar();
  v5 = strlen(key);
  for ( i = 0; i < v5; ++i )
  {
    if ( key[v3 % v5] > 64 && key[v3 % v5] <= 90 )
      key[i] = key[v3 % v5] + 32;
    ++v3;
  }
  printf("Please input your flag:");
  while ( 1 )
  {
    v1 = getchar();
    if ( v1 == 10 )
      break;
    if ( v1 == 32 )
    {
      ++v2;
    }
    else
    {
      if ( v1 <= 96 || v1 > 122 )
      {
        if ( v1 > 64 && v1 <= 90 )
        {
          str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
          ++v3;
        }
      }
      else
      {
        str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
        ++v3;
      }
      if ( !(v3 % v5) )
        putchar(32);
      ++v2;
    }
  }
  if ( !strcmp(text, str2) )
    puts("Congratulation!\n");
  else
    puts("Try again!\n");
  return __readfsqword(0x28u) ^ v11;
}
```

根据函数的核心代码可以知道，最开始的数据是

> Intel CPU/AMD CPU 计算机内部的数据存储的方式是以小端序存储的方式，因此部分数据是以颠倒方式进行存储的

```txt
text = 'killshadow'
key =  'ADSFKNDCLS'
```

现在有原始数据就可以进一步对算法进行分析

```c
while ( 1 )
{
    v1 = getchar();
    if ( v1 == 10 )
        break;
    if ( v1 == 32 )
    {
        ++v2;
    }
    else
    {
        if ( v1 <= 96 || v1 > 122 )
        {
            if ( v1 > 64 && v1 <= 90 )
            {
                str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
                ++v3;
            }
        }
        else
        {
            str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
            ++v3;
        }
        if ( !(v3 % v5) )
            putchar(32);
        ++v2;
    }
}
if ( !strcmp(text, str2) )
    puts("Congratulation!\n");
else
    puts("Try again!\n");
```

对代码观察可以发现，最终的逻辑判断是`text`的数据和`str2`的数据相等

根据对于程序的逻辑判断，编写逆向算法

```c++
#include <iostream>
#include <string>

using namespace std;

int main()
{
	int i, j, n = 0, v2 = 0, v3 = 0;;
	char v1;
	string text = "killshadow";
	string key = "ADSFKNDCLS";
	char flag[11] = { 0 };
	char str2[104] = { 0 };	
	int v5 = key.length();
	for(int i=0; i<v5; ++i)
	{
		if ( key[v3 % v5] > 64 && key[v3 % v5] <= 90 )
      		key[i] = key[v3 % v5] + 32;
    	++v3;
	}
	for (j = 0; j < 10; ++j) {
        for (v2 = 0; v2 < 10; ++v2) {
            v1 = text[v2] - 97 + 26 * j - 97 + key[v3++ % v5] + 39;
            if ((v1 >= 65 && v1 <= 90) || (v1 >= 97 && v1 <= 122)) {
                flag[v2] = v1;
                if (++n == 10) {
                    cout << flag << endl;
                    system("PAUSE");
                    return 0;
                }
            }
        }
    }
	system("PAUSE");
	return 0;
}
```

运行得到flag

```txt
KLDQCUDFZO
```



## 0x2 Java逆向解密

Java逆向的题目，本质上和安卓逆向有着异曲同工之处，可以使用安卓逆向工具进行打开，这里使用Jadx打开

```java
package defpackage;

import java.util.ArrayList;
import java.util.Scanner;

/* renamed from: Reverse  reason: default package */
public class Reverse {
    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        System.out.println("Please input the flag ：");
        String str = s.next();
        System.out.println("Your input is ：");
        System.out.println(str);
        Encrypt(str.toCharArray());
    }

    public static void Encrypt(char[] arr) {
        int[] KEY;
        ArrayList<Integer> Resultlist = new ArrayList<>();
        for (char c : arr) {
            Resultlist.add(Integer.valueOf((c + '@') ^ 32));
        }
        ArrayList<Integer> KEYList = new ArrayList<>();
        for (int i : new int[]{180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65}) {
            KEYList.add(Integer.valueOf(i));
        }
        System.out.println("Result:");
        if (Resultlist.equals(KEYList)) {
            System.out.println("Congratulations！");
        } else {
            System.err.println("Error！");
        }
    }
}
```

应该就是最基本的代码审计

关键代码其实就在`Encrypt`函数里面

```java
public static void Encrypt(char[] arr) {
        int[] KEY;
        ArrayList<Integer> Resultlist = new ArrayList<>();
        for (char c : arr) {
            Resultlist.add(Integer.valueOf((c + '@') ^ 32));
        }
        ArrayList<Integer> KEYList = new ArrayList<>();
        for (int i : new int[]{180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65}) {
            KEYList.add(Integer.valueOf(i));
        }
        System.out.println("Result:");
        if (Resultlist.equals(KEYList)) {
            System.out.println("Congratulations！");
        } else {
            System.err.println("Error！");
        }
    }
```

应该是一个注册码校验程序，写一个java程序逆过去应该就可以得到flag

```java
package re;

import java.util.ArrayList;

public class JavaRe {
	public static void main(String[] args)
	{
		ArrayList<Integer> KEYList = new ArrayList<>();
        for (int i : new int[]{180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65}) {
            KEYList.add(Integer.valueOf(i));
        }
        ArrayList<Character> Resultlist = new ArrayList<>();
        for (int c : KEYList) {
            Resultlist.add(((char)((c^ 32)-'@')));
        }
        String flag = new String();
        for(char c:Resultlist) {
        	flag += c;
        }
        System.out.println(flag);
	}

}
```

运行Java程序就可以得到flag

```txt
This_is_the_flag_!
```



## 0x3 刮开有奖

看下题目：

```txt
这是一个赌博程序，快去赚钱吧！！！！！！！！！！！！！！！！！！！！！！！！！！！(在编辑框中的输入值，即为flag，提交即可) 注意：得到的 flag 请包上 flag{} 提交
```

先查一下壳：

![image-20210901182834092](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210901182834092.png)

没壳，32位的程序，使用IDA pro打开

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  DialogBoxParamA(hInstance, (LPCSTR)0x67, 0, DialogFunc, 0);
  return 0;
}
```

看样子是调用了一个WIN32的API函数，关键的代码应该是在DialogFunc函数代码中

```c
INT_PTR __stdcall DialogFunc(HWND hDlg, UINT a2, WPARAM a3, LPARAM a4)
{
  const char *v4; // esi
  const char *v5; // edi
  int v7[2]; // [esp+8h] [ebp-20030h] BYREF
  int v8; // [esp+10h] [ebp-20028h]
  int v9; // [esp+14h] [ebp-20024h]
  int v10; // [esp+18h] [ebp-20020h]
  int v11; // [esp+1Ch] [ebp-2001Ch]
  int v12; // [esp+20h] [ebp-20018h]
  int v13; // [esp+24h] [ebp-20014h]
  int v14; // [esp+28h] [ebp-20010h]
  int v15; // [esp+2Ch] [ebp-2000Ch]
  int v16; // [esp+30h] [ebp-20008h]
  CHAR String[65536]; // [esp+34h] [ebp-20004h] BYREF
  char v18[65536]; // [esp+10034h] [ebp-10004h] BYREF

  if ( a2 == 272 )
    return 1;
  if ( a2 != 273 )
    return 0;
  if ( (_WORD)a3 == 1001 )
  {
    memset(String, 0, 0xFFFFu);
    GetDlgItemTextA(hDlg, 1000, String, 0xFFFF);
    if ( strlen(String) == 8 )
    {
      v7[0] = 90;
      v7[1] = 74;
      v8 = 83;
      v9 = 69;
      v10 = 67;
      v11 = 97;
      v12 = 78;
      v13 = 72;
      v14 = 51;
      v15 = 110;
      v16 = 103;
      sub_4010F0(v7, 0, 10);
      memset(v18, 0, 0xFFFFu);
      v18[0] = String[5];
      v18[2] = String[7];
      v18[1] = String[6];
      v4 = (const char *)sub_401000(v18, strlen(v18));
      memset(v18, 0, 0xFFFFu);
      v18[1] = String[3];
      v18[0] = String[2];
      v18[2] = String[4];
      v5 = (const char *)sub_401000(v18, strlen(v18));
      if ( String[0] == v7[0] + 34
        && String[1] == v10
        && 4 * String[2] - 141 == 3 * v8
        && String[3] / 4 == 2 * (v13 / 9)
        && !strcmp(v4, "ak1w")
        && !strcmp(v5, "V1Ax") )
      {
        MessageBoxA(hDlg, "U g3t 1T!", "@_@", 0);
      }
    }
    return 0;
  }
  if ( (_WORD)a3 != 1 && (_WORD)a3 != 2 )
    return 0;
  EndDialog(hDlg, (unsigned __int16)a3);
  return 1;
}
```

也是调用了几个WIN32的API，对代码进行分析

可以知道：

`GetDlgItemTextA` 函数是获取输入的字符串

这段代码对字符串进行了处理，主要是有两个处理函数`sub_4010F0` 和 `sub_401000`

这个函数应该是处理这个程序字符串的关键函数

先来看看sub_4010F0函数：

```c
int __cdecl sub_4010F0(int a1, int a2, int a3)
{
  int result; // eax
  int i; // esi
  int v5; // ecx
  int v6; // edx

  result = a3;
  for ( i = a2; i <= a3; a2 = i )
  {
    v5 = 4 * i;
    v6 = *(_DWORD *)(4 * i + a1);
    if ( a2 < result && i < result )
    {
      do
      {
        if ( v6 > *(_DWORD *)(a1 + 4 * result) )
        {
          if ( i >= result )
            break;
          ++i;
          *(_DWORD *)(v5 + a1) = *(_DWORD *)(a1 + 4 * result);
          if ( i >= result )
            break;
          while ( *(_DWORD *)(a1 + 4 * i) <= v6 )
          {
            if ( ++i >= result )
              goto LABEL_13;
          }
          if ( i >= result )
            break;
          v5 = 4 * i;
          *(_DWORD *)(a1 + 4 * result) = *(_DWORD *)(4 * i + a1);
        }
        --result;
      }
      while ( i < result );
    }
LABEL_13:
    *(_DWORD *)(a1 + 4 * result) = v6;
    sub_4010F0(a1, a2, i - 1);
    result = a3;
    ++i;
  }
  return result;
}
```

代码的功能暂时不太清楚，毕竟对C语言的审计功底还是不是很到位，根据代码进行转换为相应的Cpp代码运行一下：

```c++
#include <iostream>
#include <stdlib.h>
#include <stdio.h>

using namespace std;

int __cdecl sub_4010F0(char *a1, int a2, int a3)
{
    int result; // eax
    int i; // esi
    int v5; // ecx
    int v6; // edx

    result = a3;
    for (i = a2; i <= a3; a2 = i)
    {
        v5 = i;
        v6 = a1[i];
        if (a2 < result && i < result)
        {
            do
            {
                if (v6 >a1[result])
                {
                    if (i >= result)
                        break;
                    ++i;
                    a1[v5] = a1[result];
                    if (i >= result)
                        break;
                    while (a1[i] <= v6)
                    {
                        if (++i >= result)
                            goto LABEL_13;
                    }
                    if (i >= result)
                        break;
                    v5 = i;
                    a1[result] = a1[i];
                }
                --result;
            } while (i < result);
        }
    LABEL_13:
        a1[result] = v6;
        sub_4010F0(a1, a2, i - 1);
        result = a3;
        ++i;
    }
    return result;
}
int main()
{
	char v7[11];
	v7[0] = 90;
    v7[1] = 74;
    v7[2] = 83;
    v7[3] = 69;
    v7[4] = 67;
    v7[5] = 97;
    v7[6] = 78;
    v7[7] = 72;
    v7[8] = 51;
    v7[9] = 110;
    v7[10] = 103;
    cout << v7 << endl;
    sub_4010F0(v7, 0, 10);
    
    for(int i = 0;i< 11;++i){
    	cout << (int)v7[i] << "\t";
	}
	cout << endl;
	system("PAUSE");
    return 0;
}
```

运行代码，得到

```bash
ZJSECaNH3ng
51      67      69      72      74      78      83      90      97      103     110
```

看来应该是一个排序算法，按升序进行排序的

下面分析另一个函数具体是个什么东西：

```c
_BYTE *__cdecl sub_401000(int a1, int a2)
{
  int v2; // eax
  int v3; // esi
  size_t v4; // ebx
  _BYTE *v5; // eax
  _BYTE *v6; // edi
  int v7; // eax
  _BYTE *v8; // ebx
  int v9; // edi
  int v10; // edx
  int v11; // edi
  int v12; // eax
  int i; // esi
  _BYTE *result; // eax
  _BYTE *v15; // [esp+Ch] [ebp-10h]
  _BYTE *v16; // [esp+10h] [ebp-Ch]
  int v17; // [esp+14h] [ebp-8h]
  int v18; // [esp+18h] [ebp-4h]

  v2 = a2 / 3;
  v3 = 0;
  if ( a2 % 3 > 0 )
    ++v2;
  v4 = 4 * v2 + 1;
  v5 = malloc(v4);
  v6 = v5;
  v15 = v5;
  if ( !v5 )
    exit(0);
  memset(v5, 0, v4);
  v7 = a2;
  v8 = v6;
  v16 = v6;
  if ( a2 > 0 )
  {
    while ( 1 )
    {
      v9 = 0;
      v10 = 0;
      v18 = 0;
      do
      {
        if ( v3 >= v7 )
          break;
        ++v10;
        v9 = *(unsigned __int8 *)(v3 + a1) | (v9 << 8);
        ++v3;
      }
      while ( v10 < 3 );
      v11 = v9 << (8 * (3 - v10));
      v12 = 0;
      v17 = v3;
      for ( i = 18; i > -6; i -= 6 )
      {
        if ( v10 >= v12 )
        {
          *((_BYTE *)&v18 + v12) = (v11 >> i) & 0x3F;
          v8 = v16;
        }
        else
        {
          *((_BYTE *)&v18 + v12) = 64;
        }
        *v8++ = byte_407830[*((char *)&v18 + v12++)];
        v16 = v8;
      }
      v3 = v17;
      if ( v17 >= a2 )
        break;
      v7 = a2;
    }
    v6 = v15;
  }
  result = v6;
  *v8 = 0;
  return result;
}
```

看代码，发现有3和8移位的特征初步推测是base64编码，看到有一个`byte_407830`的数组，跟进点开查看数据内容

![image-20210901203207491](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210901203207491.png)

看到这数据应该就可以断定是base64编码了。

现在知道了两个函数的功能作用，可以直接进行求解，直接定位到判断条件的位置：

```c
if ( String[0] == v7[0] + 34
        && String[1] == v10
        && 4 * String[2] - 141 == 3 * v8
        && String[3] / 4 == 2 * (v13 / 9)
        && !strcmp(v4, "ak1w")
        && !strcmp(v5, "V1Ax") )
      {
        MessageBoxA(hDlg, "U g3t 1T!", "@_@", 0);
      }
```

进行简单的推断可以得出

```c
String[0] == 85; // 51+34 = 85
String[1] == 74;
String[2] == 87; //(3 x 69 +141)/4 = 87
String[3] == 80;// 2 x (90 / 9) x4 == 80
```

下面进行base64解码来得到后面四个字符的数据

```shell
b'jMp'
b'WP1'
```

根据推断出来的信息可以求解得到flag

```txt
UJWP1jMp
```



---

也可以使用Python脚本快速求解

```python
import base64

data = [51, 67, 69, 72, 74, 78, 83, 90, 97, 103, 110]
String = ""
String += chr(data[0]+34)
String += chr(data[4])
String += base64.b64decode("V1Ax").decode()
String += base64.b64decode("ak1w").decode()
flag = "flag{"+String+"}"
print(flag)
```

运行脚本就可以得到flag

```txt
flag{UJWP1jMp}
```



## 0x4 [GXYCTF2019]luck_guy

文件没有拓展名，感觉是一个ELF格式的文件

先走一下逆向的流程，首先查下壳

![image-20210902074301328](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210902074301328.png)

果然是一个ELF文件，64位的文件，用x64 IDA pro打开文件，查看主程序

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  welcome(argc, argv, envp);
  puts("_________________");
  puts("try to patch me and find flag");
  v4 = 0;
  puts("please input a lucky number");
  __isoc99_scanf("%d", &v4);
  patch_me(v4);
  puts("OK,see you again");
  return 0;
}
```

程序挺简单的，需要寻找一下核心代码

看样子核心代码应该是在`patch_me(v4)`函数里面，进入函数内部

```c
int __fastcall patch_me(int a1)
{
  int result; // eax

  if ( a1 % 2 == 1 )
    result = puts("just finished");
  else
    result = get_flag();
  return result;
}
```

继续跟进到`get_flag()`函数里面

```c
unsigned __int64 get_flag()
{
  unsigned int v0; // eax
  int i; // [rsp+4h] [rbp-3Ch]
  int j; // [rsp+8h] [rbp-38h]
  __int64 s; // [rsp+10h] [rbp-30h] BYREF
  char v5; // [rsp+18h] [rbp-28h]
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v0 = time(0LL);
  srand(v0);
  for ( i = 0; i <= 4; ++i )
  {
    switch ( rand() % 200 )
    {
      case 1:
        puts("OK, it's flag:");
        memset(&s, 0, 0x28uLL);
        strcat((char *)&s, f1);
        strcat((char *)&s, &f2);
        printf("%s", (const char *)&s);
        break;
      case 2:
        printf("Solar not like you");
        break;
      case 3:
        printf("Solar want a girlfriend");
        break;
      case 4:
        s = 0x7F666F6067756369LL;
        v5 = 0;
        strcat(&f2, (const char *)&s);
        break;
      case 5:
        for ( j = 0; j <= 7; ++j )
        {
          if ( j % 2 == 1 )
            *(&f2 + j) -= 2;
          else
            --*(&f2 + j);
        }
        break;
      default:
        puts("emmm,you can't find flag 23333");
        break;
    }
  }
  return __readfsqword(0x28u) ^ v6;
}
```

看来flag应该就在这个函数里面，本来觉得可以使用gdb调试出来，无奈自己太菜了，不知道到gdb怎么修改汇编代码进行跳转，只能进行静态分析调试

进行分析发现，`switch` 条件的顺序应该是 4 –> 5 —>1的顺序依次输出flag

写一个脚本将flag数据输出

```python
flag = 'GXY{do_not_'
f2 = [0x7F, 0x66, 0x6F, 0x60, 0x67, 0x75, 0x63, 0x69][::-1]
s = ''
for i in range(8):
    if i % 2 == 1:
        s = chr(f2[i] - 2)
    else:
        s = chr(f2[i] - 1)
    flag += s
print(flag)
```

运行脚本，得到flag

```txt
GXY{do_not_hate_me}
```



## 0x5 findit

看下题目哈

```txt
不知不觉，小明长大了，变成了一个程序员，虽然很苦逼，但是偶尔编写个小东西坑害公司新人还是蛮好玩的。新人小萌一天问小明wifi账号密码，一分钟后，小萌收到了一个文件。小萌想了好久都没得到密码，怎么办，女朋友要买东西，流量告罄，没wifi上不了网，不买就分手，是时候该展现月老的实力了兄弟们！代表月亮惩罚小明！得出答案。 注意：得到的 flag 请包上 flag{} 提交
```

感觉像是一道APK的题目，下载附件发现果然是一个APK的题目，使用APK逆向工具jadx进行逆向

```java
package com.example.findit;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends ActionBarActivity {
    /* access modifiers changed from: protected */
    @Override // android.support.v7.app.ActionBarActivity, android.support.v4.app.FragmentActivity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final EditText edit = (EditText) findViewById(R.id.widget2);
        final TextView text = (TextView) findViewById(R.id.widget1);
        final char[] a = {'T', 'h', 'i', 's', 'I', 's', 'T', 'h', 'e', 'F', 'l', 'a', 'g', 'H', 'o', 'm', 'e'};
        final char[] b = {'p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}'};
        ((Button) findViewById(R.id.widget3)).setOnClickListener(new View.OnClickListener() {
            /* class com.example.findit.MainActivity.AnonymousClass1 */

            public void onClick(View v) {
                char[] x = new char[17];
                char[] y = new char[38];
                for (int i = 0; i < 17; i++) {
                    if ((a[i] < 'I' && a[i] >= 'A') || (a[i] < 'i' && a[i] >= 'a')) {
                        x[i] = (char) (a[i] + 18);
                    } else if ((a[i] < 'A' || a[i] > 'Z') && (a[i] < 'a' || a[i] > 'z')) {
                        x[i] = a[i];
                    } else {
                        x[i] = (char) (a[i] - '\b');
                    }
                }
                if (String.valueOf(x).equals(edit.getText().toString())) {
                    for (int i2 = 0; i2 < 38; i2++) {
                        if ((b[i2] < 'A' || b[i2] > 'Z') && (b[i2] < 'a' || b[i2] > 'z')) {
                            y[i2] = b[i2];
                        } else {
                            y[i2] = (char) (b[i2] + 16);
                            if ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {
                                y[i2] = (char) (y[i2] - 26);
                            }
                        }
                    }
                    text.setText(String.valueOf(y));
                    return;
                }
                text.setText("答案错了肿么办。。。不给你又不好意思。。。哎呀好纠结啊~~~");
            }
        });
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
```

看样子好像是一个简单的加密程序，可以进行简单的分析

发现主要的flag代码：

```java
for (int i2 = 0; i2 < 38; i2++) {
    if ((b[i2] < 'A' || b[i2] > 'Z') && (b[i2] < 'a' || b[i2] > 'z')) {
        y[i2] = b[i2];
    } else {
        y[i2] = (char) (b[i2] + 16);
        if ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {
            y[i2] = (char) (y[i2] - 26);
        }
    }
}
text.setText(String.valueOf(y));
return;
```

这行代码稍加修改一下运行就可以直接俄得到flag了，写个Java的flag生成器，来生成flag吧！

```java
package re;

public class Findit {
	final static char[] b = {'p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}'};
	public static void main(String[] args)
	{
		char[] y = new char[38];
		
		for (int i2 = 0; i2 < 38; i2++) {
	        if ((b[i2] < 'A' || b[i2] > 'Z') && (b[i2] < 'a' || b[i2] > 'z')) {
	            y[i2] = b[i2];
	        } else {
	            y[i2] = (char) (b[i2] + 16);
	            if ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {
	                y[i2] = (char) (y[i2] - 26);
	            }
	        }
	    }
		System.out.println(String.valueOf(y));
	}	
}
```

运行一下这个java程序就能生成flag啦！

```txt
flag{c164675262033b4c49bdf7f9cda28a75}
```



## 0x6 简单的注册器

看下题目

```txt
生活中难免会有需要使用一些付费的程序，但是没有绿色版怎么办？只能自己逆向看看注册程序的代码是什么逻辑了。 注意：得到的 flag 请包上 flag{} 提交
```

下载附件，发现是一个apk文件，使用apk逆向工具jadx查看apk的伪代码

```java
package com.example.flag;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v7.app.ActionBarActivity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends ActionBarActivity {
    /* access modifiers changed from: protected */
    @Override // android.support.v7.app.ActionBarActivity, android.support.v4.app.FragmentActivity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (savedInstanceState == null) {
            getSupportFragmentManager().beginTransaction().add(R.id.container, new PlaceholderFragment()).commit();
        }
        final TextView textview = (TextView) findViewById(R.id.textView1);
        final EditText editview = (EditText) findViewById(R.id.editText1);
        ((Button) findViewById(R.id.button1)).setOnClickListener(new View.OnClickListener() {
            /* class com.example.flag.MainActivity.AnonymousClass1 */

            public void onClick(View v) {
                int flag = 1;
                String xx = editview.getText().toString();
                if (!(xx.length() == 32 && xx.charAt(31) == 'a' && xx.charAt(1) == 'b' && (xx.charAt(0) + xx.charAt(2)) - 48 == 56)) {
                    flag = 0;
                }
                if (flag == 1) {
                    char[] x = "dd2940c04462b4dd7c450528835cca15".toCharArray();
                    x[2] = (char) ((x[2] + x[3]) - 50);
                    x[4] = (char) ((x[2] + x[5]) - 48);
                    x[30] = (char) ((x[31] + x[9]) - 48);
                    x[14] = (char) ((x[27] + x[28]) - 97);
                    for (int i = 0; i < 16; i++) {
                        char a = x[31 - i];
                        x[31 - i] = x[i];
                        x[i] = a;
                    }
                    textview.setText("flag{" + String.valueOf(x) + "}");
                    return;
                }
                textview.setText("输入注册码错误");
            }
        });
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public static class PlaceholderFragment extends Fragment {
        @Override // android.support.v4.app.Fragment
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            return inflater.inflate(R.layout.fragment_main, container, false);
        }
    }
}
```

进行简单的代码审计，可以确定核心代码：

```java
if (flag == 1) {
    char[] x = "dd2940c04462b4dd7c450528835cca15".toCharArray();
    x[2] = (char) ((x[2] + x[3]) - 50);
    x[4] = (char) ((x[2] + x[5]) - 48);
    x[30] = (char) ((x[31] + x[9]) - 48);
    x[14] = (char) ((x[27] + x[28]) - 97);
    for (int i = 0; i < 16; i++) {
        char a = x[31 - i];
        x[31 - i] = x[i];
        x[i] = a;
    }
    textview.setText("flag{" + String.valueOf(x) + "}");
    return;
}
```

写一个Java注册器，把flag注册出来

```java
package re;

public class Register {
	public static void main(String[] args)
	{
		char[] x = "dd2940c04462b4dd7c450528835cca15".toCharArray();
	    x[2] = (char) ((x[2] + x[3]) - 50);
	    x[4] = (char) ((x[2] + x[5]) - 48);
	    x[30] = (char) ((x[31] + x[9]) - 48);
	    x[14] = (char) ((x[27] + x[28]) - 97);
	    for (int i = 0; i < 16; i++) {
	        char a = x[31 - i];
	        x[31 - i] = x[i];
	        x[i] = a;
	    }
	    System.out.println("flag{" + String.valueOf(x) + "}");
	}

}
```

运行注册器来注册一个flag

```txt
flag{59acc538825054c7de4b26440c0999dd}
```



## 0x7 [BJDCTF2020]JustRE

 下载下来是一个挺有意思的exe程序

![image-20210902121321802](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210902121321802.png)

走下流程，首先是查询文件

![image-20210902121542969](/images/BUUCTF-REVERSE-[9-16]_writeup/image-20210902121542969.png)

32位的PE程序，使用IDA pro反汇编通过检索BJD的字符串来定位到核心代码

```c
INT_PTR __stdcall DialogFunc(HWND hWnd, UINT a2, WPARAM a3, LPARAM a4)
{
  CHAR String[100]; // [esp+0h] [ebp-64h] BYREF

  if ( a2 != 272 )
  {
    if ( a2 != 273 )
      return 0;
    if ( (_WORD)a3 != 1 && (_WORD)a3 != 2 )
    {
      sprintf(String, Format, ++dword_4099F0);
      if ( dword_4099F0 == 19999 )
      {
        sprintf(String, " BJD{%d%d2069a45792d233ac}", 19999, 0);
        SetWindowTextA(hWnd, String);
        return 0;
      }
      SetWindowTextA(hWnd, String);
      return 0;
    }
    EndDialog(hWnd, (unsigned __int16)a3);
  }
  return 1;
}
```

发现核心代码中隐藏着flag的信息，得到flag

```txt
BJD{1999902069a45792d233ac}
```
