---
title: "BUUCTF REVERSE [1~8]_writeup"
date: 2021-10-14T13:03:43+08:00
draft: false
tag: ["ctf","writeup"]
toc: true
---

# BUUCTF-REVERSE-\[1-8\] writeup

逆向工程让密码学更加灵动，让密码学不再抽象。初步试水逆向工程题目，嘤嘤嘤！

![image-20210806103313499](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806103313499.png)

## 0x0 easyre

非常简单的逆向题目，这道题目解决方法很多，基本思路就使用静态调试工具进行反汇编，然后检索字符串得到flag。这里使用一个开源的工具Cutter来逆向玩玩。

![image-20210806113422474](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806113422474.png)

直接点击下面的Strings

![image-20210806114025621](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806114025621.png)

使用过滤器，快速检索flag就能得到flag

![image-20210806114828778](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806114828778.png)

得到flag

```txt
flag{this_Is_a_EaSyRe}
```

## 0x1 reverse1

先丢进IDA pro里面看看，会有什么神奇的反应和效果！

![image-20210806192321775](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806192321775.png)

然后我们需要定位到主函数，定位到主函数的方法有很多，目前，我大致有两种，首先是检索字符串，其次就 是检索函数来快速定位主函数。

通过检索字符串来定位主函数，直接检索flag

![image-20210806195615915](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806195615915.png)

然后通过检索结果定位到主函数

![image-20210806195708832](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806195708832.png)

  使用F5看到反编译的代码

![image-20210806200411241](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806200411241.png)

代码非常清晰，找到关键的代码

```c
  for ( j = 0; ; ++j )
  {
    v8 = j;
    v2 = j_strlen(Str2);
    if ( v8 > v2 )
      break;
    if ( Str2[j] == 111 )
      Str2[j] = 48;
  }
  sub_1400111D1("input the flag:");
  sub_14001128F("%20s", Str1);
  v3 = j_strlen(Str2);
  if ( !strncmp(Str1, Str2, v3) )
    sub_1400111D1("this is the right flag!\n");
  else
    sub_1400111D1("wrong flag\n");
  sub_14001113B(v5, &unk_140019D00);
  return 0i64;
}
```

进行简单地代码审计可以明确地发现

flag就藏在Str2数据中，顺着这条线找下去可以看到Str2的数据

![image-20210806210806832](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806210806832.png)

现在可以看到了flag

```txt
{hello_world}
```

不过，这道题目还没完，还是有个对于数据的变换，变换后的数据才是flag

```c
  for ( j = 0; ; ++j )
  {
    v8 = j;
    v2 = j_strlen(Str2);
    if ( v8 > v2 )
      break;
    if ( Str2[j] == 111 )
      Str2[j] = 48;
  }
```

这段代码简单来说就是将原始数据中的`o`变成`0`，进行变换后就得到flag

```txt
flag{hell0_w0rld}
```



## 0x2 reverse2

也是一道简单的逆向题目，稍微走向流程。

查看文件格式信息，由于文件没有扩展名，推测很有可能ELF格式的Linux可执行文件而不是PE文件

使用Exeinfo PE工具查一下信息

![image-20210806222154370](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806222154370.png)

发现是64位的ELF文件，使用Cutter进行反编译并进入到主函数，也就是main函数

![image-20210806232340679](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210806232340679.png)

可以找到反编译器中的关键代码

```c
    while (rbx <= rax) {
        eax = var_38h;
        rax = (int64_t) eax;
        eax = *((rax + flag));
        if (al != 0x69) {
            eax = var_38h;
            rax = (int64_t) eax;
            eax = *((rax + flag));
            if (al != 0x72) {
                goto label_1;
            }
        }
        eax = var_38h;
        rax = (int64_t) eax;
        *((rax + flag)) = 0x31;
label_1:
        var_38h++;
        eax = var_38h;
        rbx = (int64_t) eax;
        edi = "{hacking_for_fun}";
        rax = strlen ();
    }
    goto label_2;
label_0:
    rcx = &wstatus;
    eax = pid;
    edx = 0;
    rsi = rcx;
    edi = eax;
    eax = 0;
    waitpid ();
label_2:
    eax = 0;
    printf ("input the flag:");
    rax = &s2;
    rsi = rax;
    edi = "%20s";
    eax = 0;
    isoc99_scanf ();
    rax = &s2;
    eax = strcmp ("{hacking_for_fun}", rax);
    if (eax != 0) {
        puts ("wrong flag!");
    } else {
        puts ("this is the right flag!");
    }
    rdx = canary;
    rdx ^= *(fs:0x28);
    if (eax != 0) {
        stack_chk_fail ();
    }
```

对关键代码进行审计，发现原始数据是

```txt
{hacking_for_fun}
```

而且flag是对原始数据进行数据上的变换的，根据代码应该是将原始数据中的`r`和`i`进行替换，替换成了`1`

因此，最终的flag就是

```txt
flag{hack1ng_fo1_fun}
```

## 0x3 内涵的软件

日常逆向走个流程，查一下软件信息

![image-20210807135314713](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210807135314713.png)

没有壳，32位程序

丢进Cutter简单看一下，可以发现flag应该就是在反编译的文件中

![image-20210807141104750](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210807141104750.png)

结合题目的名字，应该就可以推断出来flag就是那段看起来像是flag的字段，即

```txt
flag{49d3c93df25caad81232130f3d2ebfad}
```



## 0x4 新年快乐

走下流程，先看看文件信息

![image-20210807162409975](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210807162409975.png)

发现文件被UPX进行了加壳处理

进行UPX脱壳后然后丢进Cutter就能看到flag

![image-20210807164305469](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210807164305469.png)

审计代码后可以看到flag就是

```txt
flag{HappyNewYear!}
```



## 0x5 xor

看样子像是ELF文件，使用linux的命令查询一下文件信息

```bash
file xor
```

可以得到以下信息

```txt
xor: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

可以知道应该是一个Mac OS的可执行文件，而且是一个64位的程序，丢进IDA pro里面进行逆向得到

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+2Ch] [rbp-124h]
  char __b[264]; // [rsp+40h] [rbp-110h] BYREF

  memset(__b, 0, 0x100uLL);
  printf("Input your flag:\n");
  get_line(__b, 256LL);
  if ( strlen(__b) != 33 )
    goto LABEL_7;
  for ( i = 1; i < 33; ++i )
    __b[i] ^= __b[i - 1];
  if ( !strncmp(__b, global, 0x21uLL) )
    printf("Success");
  else
LABEL_7:
    printf("Failed");
  return 0;
}
```

关键函数应该是在global数组中，下面关键就是找到这个数组里面的数据

![image-20210808061318446](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210808061318446.png)

然后顺着这个global往上找，可以找aFKWOXZUPFVMDGH这个变量，数据应该存储在这个变量中，追踪这个变量可以找到内部的数据信息

![image-20210808061948925](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210808061948925.png)

然后提取数据得到

```c
unsigned char aFKWOXZUPFVMDGH[] =
{
  102,  10, 107,  12, 119,  38,  79,  46,  64,  17, 
  120,  13,  90,  59,  85,  17, 112,  25,  70,  31, 
  118,  34,  77,  35,  68,  14, 103,   6, 104,  15, 
   71,  50,  79,   0
};
```

现在拿到数据了，下面就是对数据进行异或操作

由于异或操作是一个非常有趣的操作，就好像是在进行变魔术，非常有意思。因此可以根据异或运算的性质和特点来获取flag

写一个非常简单的异或脚本应该就能出flag了

```python
flag=""
xor=[102,  10, 107,  12, 119,  38,  79,  46,  64,  17, 
  120,  13,  90,  59,  85,  17, 112,  25,  70,  31, 
  118,  34,  77,  35,  68,  14, 103,   6, 104,  15, 
   71,  50,  79,   0]

for i in range(0,33):
    flag += chr(xor[i]^xor[i-1])
print(flag)
```

运行脚本就能得到flag

```txt
flag{QianQiuWanDai_YiTongJiangHu}
```



## 0x6 helloworld

一个APK文件，丢到jadx反编译看看吧

![image-20210808064410804](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210808064410804.png)

如果是第一次接触apk程序的逆向工程可能对apk程序的结构不是非常熟悉，不知道怎么定位的主函数。一般而言，apk文件的主函数，也就是入口函数一般都是com.example.xxxx的包里面的MainActivity函数。因此找到这个函数，点开

![image-20210808064814599](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210808064814599.png)

flag就摆出来了

```txt
flag{7631a988259a00816deda84afb29430a}
```



## 0x7 reverse3

查一下程序信息

![image-20210808084057284](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210808084057284.png)

是一个32位的程序，丢进Cutter里面看看主程序

![image-20210808084559776](/images/BUUCTF-REVERSE-[1-8]_writeup/image-20210808084559776.png)

找到主程序的反编译代码

```c
#include <stdint.h>
 
int32_t main (void) {
    int32_t var_17ch;
    int32_t var_178h;
    int32_t var_ach;
    int32_t var_a0h;
    char * dest;
    int32_t var_28h;
    int32_t var_ch;
    int32_t var_4h;
    edi = &var_17ch;
    ecx = 0x5f;
    eax = 0xcccccccc;
    memset (edi, eax, ecx);
    eax = *(0x41a004);
    eax ^= ebp;
    var_4h = eax;
    var_a0h = 0;
    while (1) {
        eax = var_a0h;
        eax++;
        var_a0h = eax;
        if (var_a0h >= 0x64) {
            goto label_0;
        }
        eax = var_a0h;
        var_178h = var_a0h;
        if (var_178h < 0x64) {
        } else {
            fcn_00411154 ();
        }
        ecx = var_178h;
        *((ebp + ecx - 0x94)) = 0;
    }
label_0:
    fcn_0041132f ("please enter the flag:");
    fcn_00411375 ("%20s", var_28h);
    esi = esp;
    eax = &var_ch;
    ecx = &var_28h;
    eax = fcn_004110c8 ();
    eax = fcn_004110be (var_28h, eax);
    uint32_t (*strncpy)(void, void) (dest, eax);
    fcn_00411127 ();
    eax = &dest;
    eax = fcn_004110c8 ();
    var_a0h = eax;
    var_ach = 0;
    while (1) {
        eax = var_ach;
        eax++;
        var_ach = eax;
        if (eax >= var_a0h) {
            goto label_1;
        }
        eax = var_ach;
        ecx = *((ebp + eax - 0x94));
        ecx += var_ach;
        edx = var_ach;
        *((ebp + edx - 0x94)) = cl;
    }
label_1:
    eax = &dest;
    eax = fcn_004110c8 ();
    esi = esp;
    uint32_t (*strncmp)(void, char*, void) (dest, "e3nifIH9b_C@n@dH", eax);
    eax = fcn_00411127 ();
    if (eax != 0) {
        fcn_0041132f ("wrong flag!\n");
    } else {
        eax = fcn_0041132f ("rigth flag!\n");
    }
    eax = 0;
    ecx = ebp;
    edx = 0x415890;
    fcn_0041126c (eax);
    ecx = var_4h;
    ecx ^= ebp;
    fcn_00411280 ();
    fcn_00411127 ();
}
```

主函数也有个关键函数 `fcn_004110be` ，定位到这个函数，看看这个函数的执行过程

```c
#include <stdint.h>
 
int32_t fcn_004110be (uint32_t arg_8h, uint32_t arg_ch, int32_t arg_10h) {
    int32_t var_100h;
    int32_t var_38h;
    int32_t var_2ch;
    size_t size;
    uint32_t var_14h;
    int32_t var_8h;
    edi = &var_100h;
    ecx = 0x40;
    eax = 0xcccccccc;
    memset (edi, eax, ecx);
    var_8h = 0;
    var_14h = 0;
    size = 0;
    if (arg_8h != 0) {
        if (arg_ch != 0) {
            goto label_1;
        }
    }
    eax = 0;
    goto label_2;
label_1:
    eax = arg_ch;
    edx = 0;
    ecx = 3;
    eax = edx:eax / ecx;
    edx = edx:eax % ecx;
    size = eax;
    edx:eax = (int64_t) eax;
    ecx = 3;
    eax = edx:eax / ecx;
    edx = edx:eax % ecx;
    if (edx != 0) {
        eax = size;
        eax++;
    }
    eax <<= 2;
    eax = arg_10h;
    ecx = size;
    *(eax) = ecx;
    eax = size;
    eax++;
    esi = esp;
    uint32_t (*malloc)(void, void, void) (eax, eax, eax);
    eax = fcn_00411127 ();
    var_14h = eax;
    if (var_14h == 0) {
        eax = 0;
        goto label_2;
    }
    eax = size;
    eax++;
    ecx = var_14h;
    fcn_004110b9 ();
    eax = arg_8h;
    var_8h = arg_8h;
    eax = arg_ch;
    size = arg_ch;
    var_2ch = 0;
    var_38h = 0;
label_0:
    if (size <= 0) {
        goto label_3;
    }
    eax = 1;
    eax <<= 1;
    *((eax + 0x41a144)) = 0;
    ecx = 1;
    ecx <<= 0;
    *((ecx + 0x41a144)) = 0;
    edx = 1;
    eax = edx * 0;
    *((eax + 0x41a144)) = 0;
    var_2ch = 0;
    while (1) {
        eax = var_2ch;
        eax++;
        var_2ch = eax;
        if (var_2ch >= 3) {
            goto label_4;
        }
        if (size < 1) {
        } else {
            eax = var_2ch;
            ecx = var_8h;
            dl = *(ecx);
            *((eax + 0x41a144)) = dl;
            eax = size;
            eax--;
            size = eax;
            eax = var_8h;
            eax++;
            var_8h = eax;
        }
    }
label_4:
    if (var_2ch == 0) {
    } else {
        eax = var_2ch;
        var_100h = var_2ch;
        if (var_100h != 1) {
            if (var_100h != 2) {
                if (var_100h != 3) {
                } else {
                    eax = 1;
                    ecx = eax * 0;
                    edx = *((ecx + 0x41a144));
                    edx >>= 2;
                    eax = var_14h;
                    eax += var_38h;
                    cl = *((edx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                    *(eax) = cl;
                    edx = var_38h;
                    edx++;
                    var_38h = edx;
                    eax = 1;
                    ecx = eax * 0;
                    edx = *((ecx + 0x41a144));
                    edx &= 3;
                    edx <<= 4;
                    eax = 1;
                    eax <<= 0;
                    ecx = *((eax + 0x41a144));
                    ecx &= 0xf0;
                    ecx >>= 4;
                    edx |= ecx;
                    eax = var_14h;
                    eax += var_38h;
                    cl = *((edx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                    *(eax) = cl;
                    edx = var_38h;
                    edx++;
                    var_38h = edx;
                    eax = 1;
                    eax <<= 6;
                    ecx = var_14h;
                    ecx += var_38h;
                    dl = *((eax + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                    *(ecx) = dl;
                    eax = var_38h;
                    eax++;
                    var_38h = eax;
                    eax = 1;
                    eax <<= 6;
                    ecx = var_14h;
                    ecx += var_38h;
                    dl = *((eax + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                    *(ecx) = dl;
                    eax = var_38h;
                    eax++;
                    var_38h = eax;
                } else {
                    eax = 1;
                }
                ecx = eax * 0;
                edx = *((ecx + 0x41a144));
                edx >>= 2;
                eax = var_14h;
                eax += var_38h;
                cl = *((edx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                *(eax) = cl;
                edx = var_38h;
                edx++;
                var_38h = edx;
                eax = 1;
                ecx = eax * 0;
                edx = *((ecx + 0x41a144));
                edx &= 3;
                edx <<= 4;
                eax = 1;
                eax <<= 0;
                ecx = *((eax + 0x41a144));
                ecx &= 0xf0;
                ecx >>= 4;
                edx |= ecx;
                eax = var_14h;
                eax += var_38h;
                cl = *((edx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                *(eax) = cl;
                edx = var_38h;
                edx++;
                var_38h = edx;
                eax = 1;
                eax <<= 0;
                ecx = *((eax + 0x41a144));
                ecx &= 0xf;
                ecx <<= 2;
                edx = 1;
                edx <<= 1;
                eax = *((edx + 0x41a144));
                eax &= 0xc0;
                eax >>= 6;
                ecx |= eax;
                edx = var_14h;
                edx += var_38h;
                al = *((ecx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                *(edx) = al;
                ecx = var_38h;
                ecx++;
                var_38h = ecx;
                eax = 1;
                eax <<= 6;
                ecx = var_14h;
                ecx += var_38h;
                dl = *((eax + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
                *(ecx) = dl;
                eax = var_38h;
                eax++;
                var_38h = eax;
            } else {
                eax = 1;
            }
            ecx = eax * 0;
            edx = *((ecx + 0x41a144));
            edx >>= 2;
            eax = var_14h;
            eax += var_38h;
            cl = *((edx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
            *(eax) = cl;
            edx = var_38h;
            edx++;
            var_38h = edx;
            eax = 1;
            ecx = eax * 0;
            edx = *((ecx + 0x41a144));
            edx &= 3;
            edx <<= 4;
            eax = 1;
            eax <<= 0;
            ecx = *((eax + 0x41a144));
            ecx &= 0xf0;
            ecx >>= 4;
            edx |= ecx;
            eax = var_14h;
            eax += var_38h;
            cl = *((edx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
            *(eax) = cl;
            edx = var_38h;
            edx++;
            var_38h = edx;
            eax = 1;
            eax <<= 0;
            ecx = *((eax + 0x41a144));
            ecx &= 0xf;
            ecx <<= 2;
            edx = 1;
            edx <<= 1;
            eax = *((edx + 0x41a144));
            eax &= 0xc0;
            eax >>= 6;
            ecx |= eax;
            edx = var_14h;
            edx += var_38h;
            al = *((ecx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
            *(edx) = al;
            ecx = var_38h;
            ecx++;
            var_38h = ecx;
            eax = 1;
            eax <<= 1;
            ecx = *((eax + 0x41a144));
            ecx &= 0x3f;
            edx = var_14h;
            edx += var_38h;
            al = *((ecx + str.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789));
            *(edx) = al;
            ecx = var_38h;
            ecx++;
            var_38h = ecx;
        }
        goto label_0;
    }
label_3:
    eax = var_14h;
    eax += var_38h;
    *(eax) = 0;
    eax = var_14h;
label_2:
    fcn_00411127 ();
    return eax;
}
```

看函数实现过程的细节像是base64的实现过程，实现之后主程序还有一个移位密码的变换

```c
    while (1) {
        eax = var_ach;
        eax++;
        var_ach = eax;
        if (eax >= var_a0h) {
            goto label_1;
        }
        eax = var_ach;
        ecx = *((ebp + eax - 0x94));
        ecx += var_ach;
        edx = var_ach;
        *((ebp + edx - 0x94)) = cl;
    }
```

变换后肯定有一个校验的过程，找到校验的数据

```txt
e3nifIH9b_C@n@dH
```

最后根据目前收集到的数据和信息编写个python脚本

（感觉挺像密码学的）

```python
import base64

c = "e3nifIH9b_C@n@dH"
m = ""
for i in range(len(c)):
    m +=chr(ord(c[i])-i)

flag = "flag"+base64.b64decode(m).decode()
print(flag)
```

运行脚本就得到flag了

```
flag{i_l0ve_you}
```
