---
title: "XCTF REVERSE Expert [13~18] Writeup"
date: 2022-01-28T19:34:08+08:00
draft: false
math: false
tags: ["ctf","writeup"]
toc: true
---

# XCTF-REVERSE-高手区-[13-18] writeup

继续玩一玩逆向的题目，感觉还是蛮有意思的。

## 0x0 srm-50

使用DIE进行探测：

![image-20211103093725322](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103093725322.png)

32位PE程序，无壳。可以尝试运行一下：

![image-20211103093811981](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103093811981.png)

应该是一个邮箱破解的程序，终于有点稍微有意思的题目了

首先进行静态分析看代码：

![image-20211103094139950](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103094139950.png)

根据WIN32的编程基础，关键函数应该是在`DialogFunc`中，登录的细节应该是在`DialogFunc`中。

跟进`DialogFunc`函数，来寻找更多的细节

```c
INT_PTR __stdcall DialogFunc(HWND hDlg, UINT a2, WPARAM a3, LPARAM a4)
{
  HMODULE v5; // eax
  HICON v6; // eax
  HMODULE v7; // eax
  HWND v8; // eax
  HCURSOR v9; // [esp-4h] [ebp-34Ch]
  CHAR String[256]; // [esp+8h] [ebp-340h] BYREF
  CHAR v11[256]; // [esp+108h] [ebp-240h] BYREF
  CHAR Text[256]; // [esp+208h] [ebp-140h] BYREF
  char Source[60]; // [esp+308h] [ebp-40h] BYREF

  if ( a2 == 16 )
  {
    EndDialog(hDlg, 0);
    return 0;
  }
  if ( a2 == 272 )
  {
    v5 = GetModuleHandleW(0);
    v6 = LoadIconW(v5, (LPCWSTR)0x67);
    SetClassLongA(hDlg, -14, (LONG)v6);
    v7 = GetModuleHandleW(0);
    v9 = LoadCursorW(v7, (LPCWSTR)0x66);
    v8 = GetDlgItem(hDlg, 1);
    SetClassLongA(v8, -12, (LONG)v9);
    return 1;
  }
  if ( a2 != 273 || (unsigned __int16)a3 != 1 )
    return 0;
  memset(String, (unsigned __int16)a3 - 1, sizeof(String));
  memset(v11, 0, sizeof(v11));
  memset(Text, 0, sizeof(Text));
  GetDlgItemTextA(hDlg, 1001, String, 256);
  GetDlgItemTextA(hDlg, 1002, v11, 256);
  if ( strstr(String, "@") && strstr(String, ".") && strstr(String, ".")[1] && strstr(String, "@")[1] != 46 )
  {
    strcpy(&Source[36], "Registration failure.");
    strcpy(Source, "Registration Success!\nYour flag is:");
    if ( strlen(v11) == 16
      && v11[0] == 67
      && v11[15] == 88
      && v11[1] == 90
      && v11[14] == 65
      && v11[2] == 57
      && v11[13] == 98
      && v11[3] == 100
      && v11[12] == 55
      && v11[4] == 109
      && v11[11] == 71
      && v11[5] == 113
      && v11[10] == 57
      && v11[6] == 52
      && v11[9] == 103
      && v11[7] == 99
      && v11[8] == 56 )
    {
      strcpy_s(Text, 0x100u, Source);
      strcat_s(Text, 0x100u, v11);
    }
    else
    {
      strcpy_s(Text, 0x100u, &Source[36]);
    }
  }
  else
  {
    strcpy_s(Text, 0x100u, "Your E-mail address in not valid.");
  }
  MessageBoxA(hDlg, Text, "Registeration", 0x40u);
  return 1;
}
```

flag直接展示的非常清晰了：

```c
if ( strstr(String, "@") && strstr(String, ".") && strstr(String, ".")[1] && strstr(String, "@")[1] != 46 )
  {
    strcpy(&Source[36], "Registration failure.");
    strcpy(Source, "Registration Success!\nYour flag is:");
    if ( strlen(v11) == 16
      && v11[0] == 67
      && v11[15] == 88
      && v11[1] == 90
      && v11[14] == 65
      && v11[2] == 57
      && v11[13] == 98
      && v11[3] == 100
      && v11[12] == 55
      && v11[4] == 109
      && v11[11] == 71
      && v11[5] == 113
      && v11[10] == 57
      && v11[6] == 52
      && v11[9] == 103
      && v11[7] == 99
      && v11[8] == 56 )
    {
      strcpy_s(Text, 0x100u, Source);
      strcat_s(Text, 0x100u, v11);
    }
    else
    {
      strcpy_s(Text, 0x100u, &Source[36]);
    }
  }
```

对`v11`数组进行运算就可以得到，非常简单，可以非常容易地得到：

```txt
CZ9dmq4c8g9G7bAX
```

故本题的flag：

```txt
CZ9dmq4c8g9G7bAX
```

## 0x1 simple-check-100

先使用DIE姐姐进行探测一下，呐呐~

![image-20211103095757150](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103095757150.png)

PE32程序，没有加壳。直接静态分析看一波：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // esp
  void *v4; // esp
  char v6; // [esp+8h] [ebp-40h] BYREF
  char v7; // [esp+1Bh] [ebp-2Dh] BYREF
  char *v8; // [esp+1Ch] [ebp-2Ch]
  int v9; // [esp+20h] [ebp-28h]
  char v10; // [esp+25h] [ebp-23h]
  char v11; // [esp+26h] [ebp-22h]
  char v12; // [esp+27h] [ebp-21h]
  char v13; // [esp+28h] [ebp-20h]
  char v14; // [esp+29h] [ebp-1Fh]
  char v15; // [esp+2Ah] [ebp-1Eh]
  char v16; // [esp+2Bh] [ebp-1Dh]
  char v17; // [esp+2Ch] [ebp-1Ch]
  char v18; // [esp+2Dh] [ebp-1Bh]
  char v19; // [esp+2Eh] [ebp-1Ah]
  char v20; // [esp+2Fh] [ebp-19h]
  char v21; // [esp+30h] [ebp-18h]
  char v22; // [esp+31h] [ebp-17h]
  char v23; // [esp+32h] [ebp-16h]
  char v24; // [esp+33h] [ebp-15h]
  char v25; // [esp+34h] [ebp-14h]
  char v26; // [esp+35h] [ebp-13h]
  char v27; // [esp+36h] [ebp-12h]
  char v28; // [esp+37h] [ebp-11h]
  char v29; // [esp+38h] [ebp-10h]
  char v30; // [esp+39h] [ebp-Fh]
  char v31; // [esp+3Ah] [ebp-Eh]
  char v32; // [esp+3Bh] [ebp-Dh]
  char v33; // [esp+3Ch] [ebp-Ch]
  char v34; // [esp+3Dh] [ebp-Bh]
  char v35; // [esp+3Eh] [ebp-Ah]
  char v36; // [esp+3Fh] [ebp-9h]
  int *v37; // [esp+40h] [ebp-8h]

  v37 = &argc;
  __main();
  v7 = 84;
  v36 = -56;
  v35 = 126;
  v34 = -29;
  v33 = 100;
  v32 = -57;
  v31 = 22;
  v30 = -102;
  v29 = -51;
  v28 = 17;
  v27 = 101;
  v26 = 50;
  v25 = 45;
  v24 = -29;
  v23 = -45;
  v22 = 67;
  v21 = -110;
  v20 = -87;
  v19 = -99;
  v18 = -46;
  v17 = -26;
  v16 = 109;
  v15 = 44;
  v14 = -45;
  v13 = -74;
  v12 = -67;
  v11 = -2;
  v10 = 106;
  v9 = 19;
  v3 = alloca(32);
  v4 = alloca(32);
  v8 = &v6;
  printf("Key: ");
  scanf("%s", v8);
  if ( check_key((int)v8) )
    interesting_function((int)&v7);
  else
    puts("Wrong");
  return 0;
}
```

关键函数是`check_key`函数，只要对`check_key`函数进行绕过应该就可以拿到flag

使用Ollydbg进行动态调试：

![image-20211103155250920](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103155250920.png)

发现Ollydbg总是会输出乱码。不能够正确地将flag输出出来，可能是由于WINDOW编码的问题，也可能是由于题目的WINDOWS程序没有写好。需要再进行对Linux程序进行分析，但是考虑到Linux程序的代码应该是和Windows的代码结构大致一致

把程序拖到Kali Linux中，使用GDB进行调试：

![image-20211103160210709](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103160210709.png)

成功调试出了flag：

```txt
flag_is_you_know_cracking!!!
```



## 0x2 Mysterious

先使用DIE探测一下：

![image-20211103163229333](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103163229333.png)

32位PE程序，无壳

尝试运行一下这个程序：

![image-20211103163501910](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103163501910.png)

密码破解的程序，先进行静态分析确定位置：

![image-20211103163903336](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103163903336.png)

经典的WIN32程序，继续跟进

![image-20211103164106092](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103164106092.png)

跟进`DialogFunc`函数，这个函数主要就是WIN32的窗口创建函数，代码逻辑应该就在WIN32中。

![image-20211103164207779](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103164207779.png)

继续跟进，胜利就在前方！

![image-20211103164237890](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103164237890.png)

找到主要的逻辑函数，在下面寻找逻辑判断语句

![image-20211103164423968](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103164423968.png)

这个`loc_401183`应该是关键函数，这个函数的地址是`0x401183`，使用Ollydbg进行同时调试来绕过这个判断条件直接出flag

使用Ollydbg，使用快捷键`CTRL+G`快速跳转到`0x401183`的地址，同时也要根据代码静态分析的逻辑来进行判断，发现需要进行输入的代码段是122，这个可以作为Key进行输入：

![image-20211103165814525](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103165814525.png)

在Ollydbg中修改汇编，修改跳转条件，然后输入122

就可以拿到flag了

![image-20211103171857297](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103171857297.png)

flag为：

```txt
flag{123_Buff3r_0v3rf|0w}
```

---

本题还有一种更简单的解法，就是直接静态分析来读取密码直接输入来拿到flag

本菜鸡只是希望可以学习到更多的技能点，于是使用另一种思路进行求解。



## 0x3 re1-100

先进行一下探测：

![image-20211103172548605](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103172548605.png)

64位的ELF文件，直接静态分析：

![image-20211103172742437](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103172742437.png)

代码中有反调试函数，这道题目使用动态调试会有些麻烦，应该是使用静态调试进行求解

查看静态调试代码

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __pid_t v3; // eax
  size_t v4; // rax
  ssize_t v5; // rbx
  bool v6; // al
  bool bCheckPtrace; // [rsp+13h] [rbp-1BDh]
  ssize_t numRead; // [rsp+18h] [rbp-1B8h]
  ssize_t numReada; // [rsp+18h] [rbp-1B8h]
  char bufWrite[200]; // [rsp+20h] [rbp-1B0h] BYREF
  char bufParentRead[200]; // [rsp+F0h] [rbp-E0h] BYREF
  unsigned __int64 v12; // [rsp+1B8h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  bCheckPtrace = detectDebugging();
  if ( pipe(pParentWrite) == -1 )
    exit(1);
  if ( pipe(pParentRead) == -1 )
    exit(1);
  v3 = fork();
  if ( v3 != -1 )
  {
    if ( v3 )
    {
      close(pParentWrite[0]);
      close(pParentRead[1]);
      while ( 1 )
      {
        printf("Input key : ");
        memset(bufWrite, 0, sizeof(bufWrite));
        gets(bufWrite);
        v4 = strlen(bufWrite);
        v5 = write(pParentWrite[1], bufWrite, v4);
        if ( v5 != strlen(bufWrite) )
          printf("parent - partial/failed write");
        do
        {
          memset(bufParentRead, 0, sizeof(bufParentRead));
          numReada = read(pParentRead[0], bufParentRead, 0xC8uLL);
          v6 = bCheckPtrace || checkDebuggerProcessRunning();
          if ( !v6 && checkStringIsNumber(bufParentRead) && atoi(bufParentRead) )
          {
            puts("True");
            if ( close(pParentWrite[1]) == -1 )
              exit(1);
            exit(0);
          }
          puts("Wrong !!!\n");
        }
        while ( numReada == -1 );
      }
    }
    close(pParentWrite[1]);
    close(pParentRead[0]);
    while ( 1 )
    {
      memset(bufParentRead, 0, sizeof(bufParentRead));
      numRead = read(pParentWrite[0], bufParentRead, 0xC8uLL);
      if ( numRead == -1 )
        break;
      if ( numRead )
      {
        if ( !childCheckDebugResult()
          && bufParentRead[0] == 123
          && strlen(bufParentRead) == '*'
          && !strncmp(&bufParentRead[1], "53fc275d81", 0xAuLL)
          && bufParentRead[strlen(bufParentRead) - 1] == 125
          && !strncmp(&bufParentRead[31], "4938ae4efd", 0xAuLL)
          && confuseKey(bufParentRead, 42)
          && !strncmp(bufParentRead, "{daf29f59034938ae4efd53fc275d81053ed5be8c}", 0x2AuLL) )
        {
          responseTrue();
        }
        else
        {
          responseFalse();
        }
      }
    }
    exit(1);
  }
  exit(1);
}
```

发现存在有一个可疑的字符串：

```txt
{daf29f59034938ae4efd53fc275d81053ed5be8c}
```

这个字符串可能是flag，但是感觉似乎有些不太对劲

往上观察，发现存在有一个进行变换的函数`confusekey`

进入这个函数：

```c
bool __cdecl confuseKey(char *szKey, int iKeyLength)
{
  char szPart1[15]; // [rsp+10h] [rbp-50h] BYREF
  char szPart2[15]; // [rsp+20h] [rbp-40h] BYREF
  char szPart3[15]; // [rsp+30h] [rbp-30h] BYREF
  char szPart4[15]; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+58h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  *(_QWORD *)szPart1 = 0LL;
  *(_DWORD *)&szPart1[8] = 0;
  *(_WORD *)&szPart1[12] = 0;
  szPart1[14] = 0;
  *(_QWORD *)szPart2 = 0LL;
  *(_DWORD *)&szPart2[8] = 0;
  *(_WORD *)&szPart2[12] = 0;
  szPart2[14] = 0;
  *(_QWORD *)szPart3 = 0LL;
  *(_DWORD *)&szPart3[8] = 0;
  *(_WORD *)&szPart3[12] = 0;
  szPart3[14] = 0;
  *(_QWORD *)szPart4 = 0LL;
  *(_DWORD *)&szPart4[8] = 0;
  *(_WORD *)&szPart4[12] = 0;
  szPart4[14] = 0;
  if ( iKeyLength != 42 )
    return 0;
  if ( !szKey )
    return 0;
  if ( strlen(szKey) != 42 )
    return 0;
  if ( *szKey != 123 )
    return 0;
  strncpy(szPart1, szKey + 1, 0xAuLL);
  strncpy(szPart2, szKey + 11, 0xAuLL);
  strncpy(szPart3, szKey + 21, 0xAuLL);
  strncpy(szPart4, szKey + 31, 0xAuLL);
  memset(szKey, 0, 0x2AuLL);
  *szKey = 123;
  strcat(szKey, szPart3);
  strcat(szKey, szPart4);
  strcat(szKey, szPart1);
  strcat(szKey, szPart2);
  szKey[41] = 125;
  return 1;
}
```

发现字符串发生了位置的变化，将位置变化还原应该就是flag

看代码可以直接对字符进行变换处理：

```txt
53fc275d81053ed5be8cdaf29f59034938ae4efd
```

本题的flag为：

```txt
53fc275d81053ed5be8cdaf29f59034938ae4efd
```



## 0x4 crazy

探测探测，看看是什么样的程序：

![image-20211103185717266](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103185717266.png)

64位的ELF程序，无壳。直接上静态分析看一看：

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rax
  __int64 v16; // rax
  char v18[32]; // [rsp+10h] [rbp-130h] BYREF
  char v19[32]; // [rsp+30h] [rbp-110h] BYREF
  char v20[32]; // [rsp+50h] [rbp-F0h] BYREF
  char v21[32]; // [rsp+70h] [rbp-D0h] BYREF
  char v22[32]; // [rsp+90h] [rbp-B0h] BYREF
  char v23[120]; // [rsp+B0h] [rbp-90h] BYREF
  unsigned __int64 v24; // [rsp+128h] [rbp-18h]

  v24 = __readfsqword(0x28u);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v18, argv, envp);
  std::operator>><char>(&std::cin, v18);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------------------------");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v4 = std::operator<<<std::char_traits<char>>(&std::cout, "Quote from people's champ");
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------------------------");
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  v6 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "*My goal was never to be the loudest or the craziest. It was to be the most entertaining.");
  std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  v7 = std::operator<<<std::char_traits<char>>(&std::cout, "*Wrestling was like stand-up comedy for me.");
  std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  v8 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "*I like to use the hard times in the past to motivate me today.");
  std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  v9 = std::operator<<<std::char_traits<char>>(&std::cout, "-------------------------------------------");
  std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
  HighTemplar::HighTemplar((DarkTemplar *)v23, (__int64)v18);
  v10 = std::operator<<<std::char_traits<char>>(&std::cout, "Checking....");
  std::ostream::operator<<(v10, &std::endl<char,std::char_traits<char>>);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v19, v18);
  func1(v20, v19);
  func2(v21, v20);
  func3(v21, 0LL);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v21);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v20);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v19);
  HighTemplar::calculate((HighTemplar *)v23);
  if ( !(unsigned int)HighTemplar::getSerial((HighTemplar *)v23) )
  {
    v11 = std::operator<<<std::char_traits<char>>(&std::cout, "/////////////////////////////////");
    std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
    v12 = std::operator<<<std::char_traits<char>>(&std::cout, "Do not be angry. Happy Hacking :)");
    std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
    v13 = std::operator<<<std::char_traits<char>>(&std::cout, "/////////////////////////////////");
    std::ostream::operator<<(v13, &std::endl<char,std::char_traits<char>>);
    HighTemplar::getFlag[abi:cxx11](v22, v23);
    v14 = std::operator<<<std::char_traits<char>>(&std::cout, "flag{");
    v15 = std::operator<<<char>(v14, v22);
    v16 = std::operator<<<std::char_traits<char>>(v15, "}");
    std::ostream::operator<<(v16, &std::endl<char,std::char_traits<char>>);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v22);
  }
  HighTemplar::~HighTemplar((HighTemplar *)v23);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v18);
  return 0;
}
```

这道题目的难点应该是C++反汇编反编译代码的阅读，需要寻找关键函数：

```c++
HighTemplar::HighTemplar((DarkTemplar *)v23, (__int64)v18); // 数据："327a6c4304ad5938eaf0efb6cc3e53dc"
HighTemplar::calculate((HighTemplar *)v23); // 加密
HighTemplar::getSerial((HighTemplar *)v23); // 验证
```

现在通过审计获得了三个关键函数，现在就可以逐一分析了

先看看加密：

```c++
bool __fastcall HighTemplar::calculate(HighTemplar *this)
{
  __int64 v1; // rax
  _BYTE *v2; // rbx
  bool result; // al
  _BYTE *v4; // rbx
  int i; // [rsp+18h] [rbp-18h]
  int j; // [rsp+1Ch] [rbp-14h]

  if ( std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length((char *)this + 16) != 32 )
  {
    v1 = std::operator<<<std::char_traits<char>>(&std::cout, "Too short or too long");
    std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
    exit(-1);
  }
  for ( i = 0;
        i <= (unsigned __int64)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length((char *)this + 16);
        ++i )
  {
    v2 = (_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                    (char *)this + 16,
                    i);
    *v2 = (*(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                       (char *)this + 16,
                       i) ^ 0x50)
        + 23;
  }
  for ( j = 0; ; ++j )
  {
    result = j <= (unsigned __int64)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length((char *)this + 16);
    if ( !result )
      break;
    v4 = (_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                    (char *)this + 16,
                    j);
    *v4 = (*(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                       (char *)this + 16,
                       j) ^ 0x13)
        + 11;
  }
  return result;
}
```

对加密代码简要分析就是：

```c
c = (((m ^ 0x50) + 23) ^ 0x13) + 11
```

然后查看一下验证函数

```c++
__int64 __fastcall HighTemplar::getSerial(HighTemplar *this)
{
  char v1; // bl
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  unsigned int i; // [rsp+1Ch] [rbp-14h]

  for ( i = 0;
        (int)i < (unsigned __int64)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length((char *)this + 16);
        ++i )
  {
    v1 = *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                     (char *)this + 80,
                     (int)i);
    if ( v1 != *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                           (char *)this + 16,
                           (int)i) )
    {
      v4 = std::operator<<<std::char_traits<char>>(&std::cout, "You did not pass ");
      v5 = std::ostream::operator<<(v4, i);
      std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
      *((_DWORD *)this + 3) = 1;
      return *((unsigned int *)this + 3);
    }
    v2 = std::operator<<<std::char_traits<char>>(&std::cout, "Pass ");
    v3 = std::ostream::operator<<(v2, i);
    std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  }
  return *((unsigned int *)this + 3);
}
```

也是对于字符`327a6c4304ad5938eaf0efb6cc3e53dc`的验证

于是这道题目就非常简单了，直接对于异或操作进行逆向求解，写个python即可求解：

```python
data='327a6c4304ad5938eaf0efb6cc3e53dc'
flag=''
for i in range(len(data)):
    n=ord(data[i])
    flag+=chr((((n-11)^0x13)-23)^0x50)
print('flag{'+flag+'}')
```

运行就能得到flag

```txt
flag{tMx~qdstOs~crvtwb~aOba}qddtbrtcd}
```



## 0x5 Windows Reverse1

探测程序：

![image-20211103200343354](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103200343354.png)

程序是32位PE程序，使用了UPX的压缩壳，需要进行程序脱壳

使用 `upx -d`命令进行脱壳

脱壳后再次检查：

![image-20211103202849197](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211103202849197.png)

脱壳之后然后进行静态分析：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+4h] [ebp-804h] BYREF
  char v5[1023]; // [esp+5h] [ebp-803h] BYREF
  char v6; // [esp+404h] [ebp-404h] BYREF
  char v7[1023]; // [esp+405h] [ebp-403h] BYREF

  v6 = 0;
  memset(v7, 0, sizeof(v7));
  v4 = 0;
  memset(v5, 0, sizeof(v5));
  printf("please input code:");
  scanf("%s", &v6);
  sub_401000(&v6);
  if ( !strcmp(&v4, "DDCTF{reverseME}") )
    printf("You've got it!!%s\n", &v4);
  else
    printf("Try again later.\n");
  return 0;
}
```

进行静态分析发现，存在一个关键函数在进行处理，即`sub_401000`函数在进行处理

跟进这个函数

```c
unsigned int __cdecl sub_401000(const char *a1)
{
  _BYTE *v1; // ecx
  unsigned int v2; // edi
  unsigned int result; // eax
  int v4; // ebx

  v2 = 0;
  result = strlen(a1);
  if ( result )
  {
    v4 = a1 - v1;
    do
    {
      *v1 = byte_402FF8[(char)v1[v4]];
      ++v2;
      ++v1;
      result = strlen(a1);
    }
    while ( v2 < result );
  }
  return result;
}
```

发现这个函数的具体实现算法相对而言是比较难以理解，当然也是本垃圾太菜了，对这个算法的逻辑搞不太清楚。

看看这个代码的汇编语句：

![image-20211104075853810](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211104075853810.png)

对汇编代码的阅读，就可以理解关键语句

```c
*v1 = byte_402FF8[(char)v1[v4]];
```

这个代码就可以转换为

```c
*v1 = byte_402FF8[(char)(v1+v4)];
```

同时，由于：

```c
v4 = a1 - v1;
```

因此：

```c
*v1 = byte_402FF8[(char)a1];
```

![image-20211104084802229](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211104084802229.png)

这样子就很好分析了，就是将`a1`进行遍历，将数据存储在v1里面。下面就是寻找`byte_402FF8`

由于本题是在进行很多地址的运算，数组也大概率被存储在更高位的地址，依着逻辑去寻找可以找到`byte_402FF8`

![image-20211104085233187](/images/XCTF-REVERSE-expert-[13-18]_writeup/image-20211104085233187.png)

应该就是下面那一坨字符，进行提取就可以了。

现在逻辑已经大致梳理清楚了，可以写个程序进行求解了：

```c++
#include <iostream>
#include <cstring>
int main()
{
  char data[]{
    126, 125, 124, 123, 122, 121, 120, 119, 118, 117, 
    116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 
    106, 105, 104, 103, 102, 101, 100,  99,  98,  97, 
     96,  95,  94,  93,  92,  91,  90,  89,  88,  87, 
     86,  85,  84,  83,  82,  81,  80,  79,  78,  77, 
     76,  75,  74,  73,  72,  71,  70,  69,  68,  67, 
     66,  65,  64,  63,  62,  61,  60,  59,  58,  57, 
     56,  55,  54,  53,  52,  51,  50,  49,  48,  47, 
     46,  45,  44,  43,  42,  41,  40,  39,  38,  37, 
     36,  35,  34,  33,  32,   0
  };
  char c[]{"DDCTF{reverseME}"};
  std::cout << "flag{";
  for(size_t i{ 0 };i < strlen(c);i++)
  {
    for(size_t j{ 0 };j < strlen(data); j++)
    {
      if(c[i] == data[j])
              putchar(32+j);
    }
  }
  std::cout << "}" << std::endl;
  return 0;
}
```

编译并运行，就能拿到flag啦：

```txt
flag{ZZ[JX#,9(9,+9QY!}
```

这道题目坑好多，而且考察的点是相对比较偏的。
