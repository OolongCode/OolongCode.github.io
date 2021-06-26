---
title: "BJDCTF 2nd CRYPTO_writeup"
date: 2021-06-26T17:01:41+08:00
draft: false
tag: ctf
toc: true
math: false
---
BJDCTF 2nd的密码学题目有8道题目可以尝试做一做，都挺有意思的。

## 0x0 签到-y1ng

来康康题目：

```txt
welcome to BJDCTF
1079822948
QkpEe1czbGMwbWVfVDBfQkpEQ1RGfQ==
```

直接使用base64解码就好：

```txt
BJD{W3lc0me_T0_BJDCTF}
```



## 0x1 老文盲了

下载附件，康康附件有什么好玩的内容：

```txt
罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝
```

不认识的文字内容，不认识怎么办？找找拼音吧，查了一下发现有个汉字转拼音的工具：[在线汉字转换拼音工具 (aies.cn)](http://www.aies.cn/pinyin.htm)

用一下这个工具得到拼音：

```txt
bì jí dì dà kuò hào zhè jiù shì fǔ lài gē zhí jiē jiāo lè bā dà kuò hào 
```

根据拼音得到flag：

```txt
BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵}
```



## 0x2 cat_flag

下载附件，康康有什么有趣的内容：

[![img](/images/BJDCTF-2nd-CRYPTO_writeup/image-13.png)](/images/BJDCTF-2nd-CRYPTO_writeup/image-13.png)

[![img](/images/BJDCTF-2nd-CRYPTO_writeup/cat.gif)](/images/BJDCTF-2nd-CRYPTO_writeup/cat.gif)

附件内容

哇哦！一个gif图片，仔细康康图片，发现猫猫挺像二进制编码的，尝试写个小脚本解决一下：

```python
import libnum
cat_list=[
        "01000010",
        "01001010",
        "01000100",
        "01111011",
        "01001101",
        "00100001",
        "01100001",
        "00110000",
        "01111110",
        "01111101"
        ]
cat_c = "".join(cat_list)
flag = libnum.n2s(int(cat_c,2))
print flag
```

运行脚本，得到flag：

```txt
BJD{M!a0~}
```



## 0x3 灵能精通-y1ng

来康康题目描述：

```txt
身经百战的Y1ng已经达到崇高的武术境界，以自律克己来取代狂热者的战斗狂怒与传统的战斗形式。Y1ng所受的训练也进一步将他们的灵能强化到足以瓦解周遭的物质世界。借由集中这股力量，Y1ng能释放灵能能量风暴来摧毁敌人的心智、肉体与器械。

得到的 flag 建议用 flag{} 包上提交。
```

感觉题目描述挺有意思，看来出题人也是玩星际的，下载附件瞧一瞧吧！

[![img](/images/BJDCTF-2nd-CRYPTO_writeup/jpg.jpg)](/images/BJDCTF-2nd-CRYPTO_writeup/jpg.jpg)附件内容

> 如果附件打不开，附件的文件名是jpg，这是个hint，可以尝试把附件的文件名扩展名修改为.jpg打开

附件内容是个图片，看样子好像猪圈密码，不过应该是猪圈密码的变形，圣堂武士密码。

圣堂武士密码是什么呢？

圣堂武士密码无非就是猪圈密码的变种，查表就可以进行求解：

![img](/images/BJDCTF-2nd-CRYPTO_writeup/20200325180259577.jpg)

圣堂武士密码表

根据圣堂武士密码的密码表进行求解：

```txt
IMKNIGHTSTEMPLAR
```

得到flag：

```txt
flag{IMKNIGHTSTEMPLAR}
```



## 0x4 燕言燕语-y1ng

瞧一瞧题目描述：

```txt
小燕子，穿花衣，年年春天来这里，我问燕子你为啥来，燕子说:
79616E7A69205A4A517B78696C7A765F6971737375686F635F73757A6A677D20
```

看样子还是比较有趣的题目，燕子说的话像是hex编码，简单进行编码解码：

```txt
yanzi ZJQ{xilzv_iqssuhoc_suzjg} 
```

像是一个移位替换密码，而且还有密钥，自然而然就联想到多表替换的维吉尼亚密码，使用维吉尼亚密码进行解密，密钥是yanzi。解密得到flag：

```txt
BJD{yanzi_jiushige_shabi} 
```



## 0x5 Y1nglish-y1ng

看看题目描述：

```txt
Y1ng根据English居然独自发明了一门语言，就叫Y1nglish

明文都是可读的英文单词，flag如果提交失败，自己读一下，把错误的单词修正，再提交(某个地方的u和i不需要调换顺序，错误点不在那里)

得到的 flag 建议用 flag{} 包上提交。
```

又是一道有意思的古典密码学题目，下载附件看一看吧！

```txt
Nkbaslk ds sef aslckdqdqst. Sef aslckdqdqst qo lzqtbw usf ufkoplkt zth oscpslsfko. Dpkfk zfk uqjk dwcko su dscqao qt dpqo aslckdqdqst, kzap su npqap qo jkfw mzoqa. Qu wse zfk qtdkfkodkh qt tkdnsfw okaefqdw, nkbaslk ds czfdqaqczdk. Bkd lk dkbb wse z odsfw.
Q nzo pzjqtv hqttkf zd z fkodzefztd npkt Pzffw Odkkbk azlk qt, pk qo z Izcztkok ufsl Izczt med tsn pk qo tsd bqjqtv qt Izczt, lzwmk Pzffw qot'd z Izcztkok tzlk med pk qo fkzbbw z Izcztkok. Pzffw nsfwkh qt z bznwkf'o suuqak wkzfo zvs, med pk qo tsn nsfwqtv zd z mztw. Pk vkdo z vssh ozbzfw, med pk zbnzwo msffsno lstkw ufsl pqo ufqktho zth tkjkf czwo qd mzaw. Pzffw ozn lk zth azlk zthozdzd dpk ozlk dzmbk. Pk pzo tkjkf msffsnkh lstkw ufsl lk. Npqbk pk nzo kzdqtv, Q zowkh pql ds bkth lk &2. Ds lw oefcfqok, pk vzjk lk dpk lstkw qllkhqzdkbw. 'Q pzjk tkjkf msfffsnkh ztw lstkw ufsl wse,' Pzffw ozqh,'os tsn wse azt czw usf lw hqttkf!' Tsn q nqbb vqjk wse npzd wse nztd.
MIH{cwdp0t_Mfed3_u0fa3_sF_geqcgeqc_ZQ_Af4aw}
```

扔到词频分析里面看一看有什么有意思的东西吧！

```txt
	Welcome to our competition. Our competition is mainly for freshmen and sophomores. There are five types of topics in this competition, each of which is very basic. If you are interested in networy security, welcome to participate. Let me tell you a story. I was having dinner at a restaurant when Harry Steele came in, he is a Japanese from Japan but now he is not living in Japan, maybe Harry isn't a Japanese name but he is really a Japanese. Harry woryed in a lawyer's office years ago, but he is now worying at a bany. He gets a good salary, but he always borrows money from his friends and never pays it bacy. Harry saw me and came andsatat the same table. He has never borrowed money from me. While he was eating, I asyed him to lend me &2. To my surprise, he gave me the money immediately. 'I have never borrrowed any money from you,' Harry said,'so now you can pay for my dinner!' Now i will give you what you want. BJD{pyth0n_Brut3_f0rc3_oR_quipquip_AI_Cr4cy}
```

看到flag了，这个会是flag吗？提交发现失败了，需要找找这flag中的错误单词呀！

```txt
BJD{pyth0n_Brut3_f0rc3_oR_quipquip_AI_Cr4cy}
```

仔细看看，可能是“Cr4cy”单词出错了，应该是“Cr4ck”，将y改成k，提交flag就成功了！

```txt
BJD{pyth0n_Brut3_f0rc3_oR_quipquip_AI_Cr4ck}
```



## 0x6 rsa0

终于看到了满怀期待的RSA题目了，这个题目需要nc连接，打开kali使用nc连一下：

[![img](/images/BJDCTF-2nd-CRYPTO_writeup/image-15-1024x121.png)](/images/BJDCTF-2nd-CRYPTO_writeup/image-15.png)nc连接

nc获取了一些信息：

```
e=10477063

p+q=17797691537345386808732394196803681705577569713058967120949517816644062502139647331474144263789043199741290898466578874059252164582901136367451369351827816

p-q=1305460584852976150632619140303339956209228307006605810393373145443065968179582165859467446565684139103706614652868361938441145461112269668449569764472982

c=39163440507451196385175391692403807512116238503431942217244080791066873723780085527827581471431177375753278940397090368658088104095247010524149681791425756148064544080426058546466326660811194616137132601269623860143290910244742205045745875133012498997510445277485057284790297158770357940730856250397868755440

flag=??????
```

应该是一道简单的解方程题目，编写python脚本处理一下：

```python
import sympy
import libnum
e=10477063

pq_add=17797691537345386808732394196803681705577569713058967120949517816644062502139647331474144263789043199741290898466578874059252164582901136367451369351827816

pq_reduce=1305460584852976150632619140303339956209228307006605810393373145443065968179582165859467446565684139103706614652868361938441145461112269668449569764472982

c=39163440507451196385175391692403807512116238503431942217244080791066873723780085527827581471431177375753278940397090368658088104095247010524149681791425756148064544080426058546466326660811194616137132601269623860143290910244742205045745875133012498997510445277485057284790297158770357940730856250397868755440

p = sympy.Symbol('p')
q = sympy.Symbol('q')
result = sympy.solve([p+q-pq_add,p-q-pq_reduce],[p,q])
p = int(result[p])
q = int(result[q])
n = p*q
phi = (p-1)*(q-1)
d = libnum.invmod(e,phi)
m = pow(c,d,n)
flag = libnum.n2s(m)
print flag
```

运行脚本，得到flag：

```txt
flag{562f22b9-400d-4ec9-aa76-cd616aac90f1}
```



## 0x7 rsa1

RSA题目，这道题目同样也需要nc进行一下连接才能看到信息，用kali连一下吧！

[![img](/images/BJDCTF-2nd-CRYPTO_writeup/image-16-1024x136.png)](/images/BJDCTF-2nd-CRYPTO_writeup/image-16.png)nc连接

通过nc连接可以得到如下信息：

```txt
e=13978249

p^2+q^2=151633530567840355748243871671727511189658909500927250886437120180748983135296331316827920586717252371861785059822420509109728958374451816184682503257816598163005301542586939209069221866722313318463885766603690164708951344417890956348605521584906780834058177779608801835165928975303416040686406630968929531010

p-q=-2118796405660557026785910948566097381644078577714422876494681451389305041193569373390033403177726098952539178824903786390753214478292445023621601397654014

c=21916668537159292929146888499738761128788996251113020794961311339328734967861189157533491528242915717785269949067916125251437612282270561594687073731637132301015100520285933737661576838469743738400472236913537499783613239148851084298950840310231212420378731161267913668383166553730465799427960831384019988540

flag=??????
```

还是比较类似的考察方法，依旧是解方程，编写一个小脚本求解吧！

```python
import sympy
import libnum
e=13978249

f1=151633530567840355748243871671727511189658909500927250886437120180748983135296331316827920586717252371861785059822420509109728958374451816184682503257816598163005301542586939209069221866722313318463885766603690164708951344417890956348605521584906780834058177779608801835165928975303416040686406630968929531010

f2=-2118796405660557026785910948566097381644078577714422876494681451389305041193569373390033403177726098952539178824903786390753214478292445023621601397654014

c=21916668537159292929146888499738761128788996251113020794961311339328734967861189157533491528242915717785269949067916125251437612282270561594687073731637132301015100520285933737661576838469743738400472236913537499783613239148851084298950840310231212420378731161267913668383166553730465799427960831384019988540


p = sympy.Symbol('p')
q = sympy.Symbol('q')
result = sympy.solve([p**2+q**2-f1,p-q-f2],[p,q])
# print result
p = int(result[1][0])
q = int(result[1][1])
# print p,q

n = p*q
phi = (p-1)*(q-1)
d = libnum.invmod(e,phi)
m = pow(c,d,n)
flag = libnum.n2s(m)
print flag
```

运行脚本，得到flag：

```txt
flag{db0f7d6f-da5a-413b-8dfa-1a82a004c083}
```



BJD 2nd的Crypto题目全部求解，脑洞题目偏多，整体考察比较综合，难度相对较低。
