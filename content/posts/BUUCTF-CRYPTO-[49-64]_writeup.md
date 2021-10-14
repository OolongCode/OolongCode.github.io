---
title: "BUUCTF CRYPTO [49~64]_writeup"
date: 2021-06-26T17:20:25+08:00
draft: false
tags: ["ctf","writeup"]
toc: true
math: false
---
沉浸在密码学的世界里面，缓缓浸入题目的海洋，16道crypto题目！

[![img](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-17-1024x673.png)](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-17.png)

这次的题目，难度也开始逐渐上来咯！当然不仅仅只有难度，还有脑洞！

[![img](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-18.png)](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-18.png)

## 0x0 古典密码知多少

应该是考察古典密码的题目，点开题目下载附件，瞧一瞧

[![img](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-19.png)](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-19.png)

打开图片就察觉到这题可能会非常草……，果然古典的恶心，应该是三种古典密码的组合，可以清晰地看出有猪圈密码和变种圣堂武士密码，至于剩下那一种密码实在是找不到……，只能无奈地去瞧一瞧[大佬的wp](https://blog.ysneko.com/archives/115/)，发现是标准银河字母。根据得到的信息进行比对，蓝色的是猪圈密码，橙色的是圣堂武士密码，黑色的是标准银河字母。根据信息，进行解密得：

```txt
FGCPFLIRTUASYON
```

看样子应该还有一层加密，最常见的古典加密方法就是凯撒加密和栅栏密码，经过尝试发现是栅栏密码，使用栅栏密码进行解密得到flag：

```txt
FLAGISCRYPTOFUN
```

------

猪圈密码对照表：

![img](/images/BUUCTF-CRYPTO-[49-64]_writeup/20201019010012173.png)

圣堂武士密码对照表：

![此图像的alt属性为空；文件名为20200325180259577.jpg](/images/BUUCTF-CRYPTO-[49-64]_writeup/20200325180259577.jpg)

标准银河字母对照表：

![查看源图像](/images/BUUCTF-CRYPTO-[49-64]_writeup/t01cf49fe8b6c515f04.png)



## 0x1 [HDCTF2019]bbbbbbrsa

看来又是熟悉的RSA题目，嘤嘤嘤~

下载附件，打开发现有两个文件，一个enc文件，一个encode.py文件

enc文件：

```txt
p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = ==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM
```

encode.py文件：

```python
from base64 import b64encode as b32encode
from gmpy2 import invert,gcd,iroot
from Crypto.Util.number import *
from binascii import a2b_hex,b2a_hex
import random

flag = "******************************"

nbit = 128

p = getPrime(nbit)
q = getPrime(nbit)
n = p*q

print p
print n

phi = (p-1)*(q-1)

e = random.randint(50000,70000)

while True:
	if gcd(e,phi) == 1:
		break;
	else:
		e -= 1;

c = pow(int(b2a_hex(flag),16),e,n)

print b32encode(str(c))[::-1]

# 2373740699529364991763589324200093466206785561836101840381622237225512234632
```

题目给了n、p、c而没有给e，根据python源码 e需要爆破一下，写个小脚本解决这道题目：

```python
import libnum
import gmpy2
from base64 import b64decode as b32decode


p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = '==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM'

q = n // p
phi = (p-1)*(q-1)
c = int(b32decode(str(c)[::-1]))
for e in range(50000,70000):
    if gmpy2.gcd(e,phi) == 1:
        d = gmpy2.invert(e,phi)
        m = pow(c,d,n)
        flag = libnum.n2s(m)
        if 'flag' in str(flag):
            print 'e=%d'%e
            print flag
            break
```

运行脚本，得到flag：

```txt
flag{rs4_1s_s1mpl3!#}
```



## 0x2 [BJDCTF2020]RSA

RSA题目，妙呀！下载附件看看：

```python
from Crypto.Util.number import getPrime,bytes_to_long

flag=open("flag","rb").read()

p=getPrime(1024)
q=getPrime(1024)
assert(e&lt;100000)
n=p*q
m=bytes_to_long(flag)
c=pow(m,e,n)
print c,n
print pow(294,e,n)

p=getPrime(1024)
n=p*q
m=bytes_to_long("BJD"*32)
c=pow(m,e,n)
print c,n

'''
output:
12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120  13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018
979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721  12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
'''
```

一个python源程序，看样子还是有点意思的，发现这里有三个密文，两个n数值，两个n的数值是共用同一个q值，可以使用欧几里得算法求出q，e给出了范围，应该是使用爆破的方法求出e的数值，这里写个小脚本：

```python
import libnum
import gmpy2

c = 12641635617803746150332232646354596292707861480200207537199141183624438303757120570096741248020236666965755798009656547738616399025300123043766255518596149348930444599820675230046423373053051631932557230849083426859490183732303751744004874183062594856870318614289991675980063548316499486908923209627563871554875612702079100567018698992935818206109087568166097392314105717555482926141030505639571708876213167112187962584484065321545727594135175369233925922507794999607323536976824183162923385005669930403448853465141405846835919842908469787547341752365471892495204307644586161393228776042015534147913888338316244169120
n = 13508774104460209743306714034546704137247627344981133461801953479736017021401725818808462898375994767375627749494839671944543822403059978073813122441407612530658168942987820256786583006947001711749230193542370570950705530167921702835627122401475251039000775017381633900222474727396823708695063136246115652622259769634591309421761269548260984426148824641285010730983215377509255011298737827621611158032976420011662547854515610597955628898073569684158225678333474543920326532893446849808112837476684390030976472053905069855522297850688026960701186543428139843783907624317274796926248829543413464754127208843070331063037
_294_c =381631268825806469518166370387352035475775677163615730759454343913563615970881967332407709901235637718936184198930226303761876517101208677107311006065728014220477966000620964056616058676999878976943319063836649085085377577273214792371548775204594097887078898598463892440141577974544939268247818937936607013100808169758675042264568547764031628431414727922168580998494695800403043312406643527637667466318473669542326169218665366423043579003388486634167642663495896607282155808331902351188500197960905672207046579647052764579411814305689137519860880916467272056778641442758940135016400808740387144508156358067955215018
BJD_c = 979153370552535153498477459720877329811204688208387543826122582132404214848454954722487086658061408795223805022202997613522014736983452121073860054851302343517756732701026667062765906277626879215457936330799698812755973057557620930172778859116538571207100424990838508255127616637334499680058645411786925302368790414768248611809358160197554369255458675450109457987698749584630551177577492043403656419968285163536823819817573531356497236154342689914525321673807925458651854768512396355389740863270148775362744448115581639629326362342160548500035000156097215446881251055505465713854173913142040976382500435185442521721
BJD_n = 12806210903061368369054309575159360374022344774547459345216907128193957592938071815865954073287532545947370671838372144806539753829484356064919357285623305209600680570975224639214396805124350862772159272362778768036844634760917612708721787320159318432456050806227784435091161119982613987303255995543165395426658059462110056431392517548717447898084915167661172362984251201688639469652283452307712821398857016487590794996544468826705600332208535201443322267298747117528882985955375246424812616478327182399461709978893464093245135530135430007842223389360212803439850867615121148050034887767584693608776323252233254261047
q = gmpy2.gcd(n,BJD_n)
p = n // q
e = 0
for i in range(100000):
    if _294_c == pow(294,i,n):
        e = i
        break

phi = (p-1)*(q-1)
d = gmpy2.invert(e,phi)
m = pow(c,d,n)
flag = libnum.n2s(m)
print flag
```

运行脚本，得到flag：

```txt
BJD{p_is_common_divisor}
```



## 0x3 [WUSTCTF2020]佛说：只能四天

看题目还挺有意思的，应该是一道古典密码学题目，看下题目描述：

```txt
圣经分为《旧约全书》和《新约全书》
```

再看下题目：

```txt
尊即寂修我劫修如婆愍闍嚤婆莊愍耨羅嚴是喼婆斯吶眾喼修迦慧迦嚩喼斯願嚤摩隸所迦摩吽即塞願修咒莊波斯訶喃壽祗僧若即亦嘇蜜迦須色喼羅囉咒諦若陀喃慧愍夷羅波若劫蜜斯哆咒塞隸蜜波哆咤慧聞亦吽念彌諸嘚嚴諦咒陀叻咤叻諦缽隸祗婆諦嚩阿兜宣囉吽色缽吶諸劫婆咤咤喼愍尊寂色缽嘚闍兜阿婆若叻般壽聞彌即念若降宣空陀壽愍嚤亦喼寂僧迦色莊壽吽哆尊僧喼喃壽嘚兜我空所吶般所即諸吽薩咤諸莊囉隸般咤色空咤亦喃亦色兜哆嘇亦隸空闍修眾哆咒婆菩迦壽薩塞宣嚩缽寂夷摩所修囉菩阿伏嘚宣嚩薩塞菩波吶波菩哆若慧愍蜜訶壽色咒兜摩缽摩諦劫諸陀即壽所波咤聞如訶摩壽宣咤彌即嚩蜜叻劫嘇缽所摩闍壽波壽劫修訶如嚩嘇囉薩色嚤薩壽修闍夷闍是壽僧劫祗蜜嚴嚩我若空伏諦念降若心吽咤隸嘚耨缽伏吽色寂喃喼吽壽夷若心眾祗喃慧嚴即聞空僧須夷嚴叻心願哆波隸塞吶心須嘇摩咤壽嘚吶夷亦心亦喃若咒壽亦壽囑囑
```

唔，好像还有hint，去瞧一瞧：

```txt
1. 虽然有点不环保，但hint好像是一次性的，得到后就没有利用价值了。
2. 凯撒不是最后一步，by the way，凯撒为什么叫做凯撒？
```

新约全书和旧约全书，用[与佛论禅](https://www.keyfc.net/bbs/tools/tudoucode.aspx)解不出来，“新约全书”可能是提示吧，最后用[新约佛论禅](http://hi.pcmoe.net/Buddha.html)解得(注意前面要加上“佛曰：”)：

```txt
平等文明自由友善公正自由诚信富强自由自由平等民主平等自由自由友善敬业平等公正平等富强平等自由平等民主和谐公正自由诚信平等和谐公正公正自由法治平等法治法治法治和谐和谐平等自由和谐自由自由和谐公正自由敬业自由文明和谐平等自由文明和谐平等和谐文明自由和谐自由和谐和谐平等和谐法治公正诚信平等公正诚信民主自由和谐公正民主平等平等平等平等自由和谐和谐和谐平等和谐自由诚信平等和谐自由自由友善敬业平等和谐自由友善敬业平等法治自由法治和谐和谐自由友善公正法治敬业公正友善爱国公正民主法治文明自由民主平等公正自由法治平等文明平等友善自由平等和谐自由友善自由平等文明自由民主自由平等平等敬业自由平等平等诚信富强平等友善敬业公正诚信平等公正友善敬业公正平等平等诚信平等公正自由公正诚信平等法治敬业公正诚信平等法治平等公正友善平等公正诚信自由公正友善敬业法治法治公正公正公正平等公正诚信自由公正和谐公正平等
```

又是套套，应该是社会主义核心价值观密码，使用[在线工具](http://ctf.ssleye.com/cvencode.html)解密一下：

```txt
RLJDQTOVPTQ6O6duws5CD6IB5B52CC57okCaUUC3SO4OSOWG3LynarAVGRZSJRAEYEZ_ooe_doyouknowfence
```

发现后面有一个提示，好像是栅栏密码，需要进行解密，使用[在线工具](https://www.qqxiuzi.cn/bianma/zhalanmima.php)解一下：

```txt
R5UALCUVJDCGD63RQISZTBOSO54JVBORP5SAT2OEQCWY6CGEO53Z67L_doyouknowCaesar
```

后面又有提示，应该是凯撒密码，由于hint说凯撒密码不是最后一步，因此看密文格式像是base32加密的格式，因此这里需要进行测试检验，经过检验发现是3位的凯撒密码可以成功使用base32。故使用3位凯撒密码解密：

```txt
O5RXIZRSGAZDA63ONFPWQYLPL54GSYLOM5PXQ2LBNZTV6ZDBL53W67I
```

然后使用base32解密，即可：

```txt
wctf2020{ni_hao_xiang_xiang_da_wo}
```



## 0x4 [MRCTF2020]天干地支+甲子

看样子是蛮有意思的样子~，看看题目到底是个啥：

```txt
得到得字符串用MRCTF{}包裹
一天Eki收到了一封来自Sndav的信，但是他有点迷希望您来解决一下
甲戌
甲寅
甲寅
癸卯
己酉 
甲寅
辛丑
```

看题目应该是考察的是六十甲子纳音表：（和BUUCTF上的传统文化+古典密码那道题目非常类似，估计思路也是相似的）

[![img](http://zkinghar.top/wp-content/uploads/2021/04/image-139.png)](http://zkinghar.top/wp-content/uploads/2021/04/image-139.png)

根据六十甲子纳音表编写脚本：

```python
c_sky = "甲乙丙丁戊己庚辛壬癸"
c_earth = "子丑寅卯辰巳午未申酉戌亥"
c_dict = {}
for i in range(60):
    c_dict[c_sky[i%len(c_sky)]+c_earth[i%len(c_earth)]] = i+1

c = "甲戌 甲寅 甲寅 癸卯 己酉 甲寅 辛丑"
c_list = c.split(" ")
m_list = []

for i in c_list:
    m_list.append(chr(c_dict[i]+60))

m = "".join(m_list)
print(m)
```

运行脚本，得到flag：（注意要python3环境下运行哟！）

```txt
Goodjob
```



## 0x5 [MRCTF2020]vigenere

看样子应该是维吉尼亚密码，也就是考察多表替换密码的题目，看看题目有些什么东西吧！

两个文件，一个cipher.txt密文文件，一个vigenere.py加密源码文件

vigenere.py文件

```python
#!/bin/python3
from ctf import source_text, key_string

getdiff = lambda char: ord(char)-ord('a')
getchar = lambda num: chr(ord('a')+num)

def vigenere(src: chr, key: chr) -&gt; chr:
    assert(src.isalpha() and key.isalpha())
    return(getchar((getdiff(src) + getdiff(key) + 1) % 26))

src = source_text.lower()
count = 0
assert(len(key_string) &gt; 5 and len(key_string) &lt; 10)
for i in src:
    if(i.isalpha()):
        print(vigenere(i, key_string[count % len(key_string)]), end='')
        count+=1
    else:
        print(i, end='')
```

cipher.txt

```txt
g vjganxsymda ux ylt vtvjttajwsgt bl udfteyhfgt
oe btlc ckjwc qnxdta 
vbbwwrbrtlx su gnw nrshylwmpy cgwps, lum bipee ynecgy gk jaryz frs fzwjp, x puej jgbs udfteyhfgt, gnw sil uuej su zofi. sc okzfpu bl lmi uhzmwi, x nyc dsj bl lmi enyl ys argnj yh nrgsi. nba swi cbz ojprbsw fqdam mx. cdh nsai cb ygaigroysxn jnwwi lr msylte.
cw mekr tg jptpzwi kdikjsqtaz, ftv pek oj pxxkdd xd ugnj scr, yg n esqxwxw nba onxw au ywipgkj fyiuujnxn gnss xwnz onxw jnahl avhwwxn vzkjpu nrofch fvwfoh. v jwhppek lmi vyutfp hbiafp hcguj at nxw gyxyjask ib hw seihxsqpn vtvjttajwsx ds zzj xnegfsmtf egz wtrq lt mbcukj sc hy. qty wnbw ss bbxsq vxtnl ys ghrw zw cbx vt cdh vgxwtfy ssc brzzthh bl wsjdeiwricg cw mekr zjzi grgktr ib lwfv.
vbbwwrbrtlx hteonj xwroj oyhg vgbigf ljtq iuk utrhrtl tj iuk ytztetwi. cdh nsai crolmig fudngxgkv ssg ekujmkrj gzvh. jk vnh cbz aszxgk qty. nba vt rdg qfta jf, tgw hd lum prdj umw aderv. hcqrxkuerr jgjw cbz dni lvzznr nbaj gsgqkjx. hd aul ylxaq lmei lum hec oaaqh xg, gk yldhmz nx lrxw f tjorah gdaylwyrgogs tgbpwhx. nba ufrcbz. ay mh nt shx ds tsyygr gfi mi txgbw xgywqj iuxgzkw baj hsaykuymkr guymday.
qty wnbw ssi rtyfktq of tyg txwfx paj yfxwrxask rbtnjvhnzatr, cbx vnh nba uwipgk lmi lrgdyl ds umw qpeqwytaniwx. cdh jg ssi xtgb sje imqxjek, gzv tgnahw, de zzj ycjxayxta igiih gnsy eaeksic eeunnht baj xsrvkld qdek gwhte zzfr rbadi ft bhlfmcrj td ecl ux dsje oeushvzatrh.
lum hppvs lmigr gjj tgbhdjqh nsgsk jf zzfx nba fjis gu ktpkr. egz yhr zznw rygar eh nt wcgjfk lt mcigvj sje vjjgxailx. qpae gk xwryw uvdorwrw sbt'l jbxfz. omigr zzjvt nxw wipy igsjavilx, awrxw yltek swi leuflw, lr caqp xqkfymul zzjq paj sihgryk yltz hq tyg zkssw. lr gjj jdesask dhx gbr hbiafp rbtlwerg. zznw vbbwwrpaiw bmay gjnwt niutvsvty ys iuk utrsvzatrh bl gzv lbxdi, rdg egzvh. baj bsgyj ax hxslwwicg.
iqgigfvshi rbtknwif ux yvpayshxxbtk, wianzatrhuohx, ecq zztyvuz aywtyl, swvplkv qmzr g kyecqofl apik as xwr cwg su baj hsbzafngpgogsw. dhxk nw p jujqh iugl nw qbzz jzteeomigr gfi rdjnwwi, qhz ay mh aul bltek tthxry dnzt.
jk swi reksymct g otvaq zzfx pyr efc tazww axgngzx eeonnpttk gw tgrpmimrr guhsgqkv gc gniw, jgdaueng ebcww, qxyolfvn sujhi, de ylfxxbt gk fxezz.
bi pek uwipgofl e lbxdi awrxw frnbtw, frnjnwwi bne wctgryk mmh bx zjv qrrajjh, au efxirx zta hvtyzppe, cayldhz xjeg bl tjmct igjvrrj asxd fodjrrr uj hscsujrmil.
egzv armsq gdaiwuxh bl hwserxld, imcxwxwxbt, aiicgold, qdikejri, ntv hscgkpy hd aul fteye lt yh. gnwd egr gdq fpfkv tr bnzljv, paj lmigr ok ss bnzljv wrxw.
tyg vjwsxxgowx lpik ft fdqowx, wd, htdnot lum, bi rntftx dozsnr dejww fn cnqxmrnr utigpogs. at okdnikr zzfx ueue jxwvik, jravmzyicrj kjpu-vtljvtfz, ssh iuk utqbbtojea, baj lskrxffrrr caqp tzkjli. dhx aiicgolnih zgq gi svylwmqhzwi ereukx qpae gk cdhx bzvxfjahxxbtk. ylt btdd ppj zzfx pyr gzv rbtkymihkfy gjyzmwih jumqh vrtwweaye jjgdttaei xf zzj kdyjws vjyk. oj ldck oj axyr tj eqyk lt fjvrv tyg cgjymrhrsw wdyalnscf uf ylpg hsxmh. oal bi rntftx ppiwux iuk ktpjgogsw nba swi pgzwrtivty ys xzvgxi.
xa zzj ycvzwi winzwx, cdh nsai ibjsd ggrgljh p ygo, ylt gkdjgdzsmsmrnzatrh ekxtvb nil, blxpn jjtjqosyih lumw sla igswivzmymda gfi mcfadyw iuk vwipzy gk ntslwwwda, csxlxamltr, bvrd, resvygs, htguizikvrdj, ecq hjfrsrok. yltfk vwipzy ezwi auo gi qbxf frtj of zw.
nba swi irxjnjxrj gk cdhx gbr ruodivta, yasgt gnwd egr tsymkry as e lbxdi awrxw dsj jodq eajgqx ft vsenkgntlx. ftpgmxi nba xjeg gnwr, cdh kfyvjfz qtyg oajjejpxshmtf cayl iuk hfvtazsq vtfvgswxoodnxxry qty pek lts rbcswhal zg hscsxgsx nbajxiaikk. nr dhx otvaq, gdq xwr ywsxxzkfyw paj wctgryknscf ux mybntayc, ueue ylt qktfwxam lt xwr gfliavi, swi enxlx su n ywfqaryk bldyk, lmi vyutfp rbtnjvhnzatr ds hayw. lr issrdg ywuegnzw ylt noj ylpg iztotf ljtq iuk snv jcuf blxpn onrvf hwfx.
xa iznrp, tkjrecl, ljfrrr, xmxwxn, yaskpcujj, minrq frs gnw zrxgkv xxpgkk, dsj nxw yvnvty ys lnxv tju gnw amghy gk pxokjyc ql kjjgivty lypej htwif gl ylt sxgsxxrxk tj rlhwwweniw. yltfk efc zrkh tyi gnw hscggynsc suj f wbnrd ymbr, hmy xwre onpa aul bsgx of f aderv ylpg caqp hbuf gi qygfpiirj as fxg-hwfvxam ejhxn.
egzv xaijjehvtyqc doygqiir ofksgzglnsc vtvzwieowx adhrv uigcklzeir zzjqhrrnjw ql vjttdfofl ppjy, as ebrxahe paj wqwtjnwwi, iugl hppvs lt sla yhjiru olxias zzwsjtngzx iuk otvaq. zzjwt ygox adhrv iirygjj msrgk ys qr gftxwrx ashjfzjnea cxgiyrg, tg rsgr tggpt gnss txt ojtr. xa umw aderv, blpgknjv iuk zzqpa sash bne uwipgk ufr qr xwuvdqaujh paj vnwieotzxtq ofkmcvzwqc pg tg hshg. zzj kabhsq gdabwdecpk gk xwbaymx cb rgskte xwvyxekk dsje lshxdeowx xd niutqeyokm.
xwryw nrreksxmctrq mshgodj ecq igqscvgd ripfajjw eyguj yh vt lmi hnsw ushvzatr pf zztwt cxwamdhy dtztey gk jgrkvtq paj kjpu-qkljvbvtsymda czt lpq zg wiyril ylt nalmsgvzajw ds jaxxpaz, msmcsujris cuojvh. jk ezwi qkuqegr umw zxezmfp hrrnjw xzsmsi ib egzv hbbwwixttld, ikrt sx at pufymchk lt gdaywsx ib egzv ghrw tzte umw fdqowx. at jodq weeksi sjeywqztf guwshf zzj tantwy wd gnsy rd btw hec nxjjwi baj yldhmzyw.
lr caqp reksyi p ponnpxmglnsc bl lmi bvtv nr rlhwwweniw. ren vz tj qdek zzqpak ssh unoj ylpa zzj aderv dsje mgaigaswsxh ugnj qpqk tjjdek.
xqev vy ewgis balicrxw hvnczg hvppq efr, eyksxi pqj mshteyutvt ntv hygye twerry.
```

尝试使用[在线工具](https://www.guballa.de/vigenere-solver)进行维吉尼亚密码的解密：

```txt
a declaration of the independence of cyberspace
by john perry barlow 
governments of the industrial world, you weary giants of flesh and steel, i come from cyberspace, the new home of mind. on behalf of the future, i ask you of the past to leave us alone. you are not welcome among us. you have no sovereignty where we gather.
we have no elected government, nor are we likely to have one, so i address you with no greater authority than that with which liberty itself always speaks. i declare the global social space we are building to be naturally independent of the tyrannies you seek to impose on us. you have no moral right to rule us nor do you possess any methods of enforcement we have true reason to fear.
governments derive their just powers from the consent of the governed. you have neither solicited nor received ours. we did not invite you. you do not know us, nor do you know our world. cyberspace does not lie within your borders. do not think that you can build it, as though it were a public construction project. you cannot. it is an act of nature and it grows itself through our collective actions.
you have not engaged in our great and gathering conversation, nor did you create the wealth of our marketplaces. you do not know our culture, our ethics, or the unwritten codes that already provide our society more order than could be obtained by any of your impositions.
you claim there are problems among us that you need to solve. you use this claim as an excuse to invade our precincts. many of these problems don't exist. where there are real conflicts, where there are wrongs, we will identify them and address them by our means. we are forming our own social contract. this governance will arise according to the conditions of our world, not yours. our world is different.
cyberspace consists of transactions, relationships, and thought itself, arrayed like a standing wave in the web of our communications. ours is a world that is both everywhere and nowhere, but it is not where bodies live.
we are creating a world that all may enter without privilege or prejudice accorded by race, economic power, military force, or station of birth.
we are creating a world where anyone, anywhere may express his or her beliefs, no matter how singular, without fear of being coerced into silence or conformity.
your legal concepts of property, expression, identity, movement, and context do not apply to us. they are all based on matter, and there is no matter here.
our identities have no bodies, so, unlike you, we cannot obtain order by physical coercion. we believe that from ethics, enlightened self-interest, and the commonweal, our governance will emerge. our identities may be distributed across many of your jurisdictions. the only law that all our constituent cultures would generally recognize is the golden rule. we hope we will be able to build our particular solutions on that basis. but we cannot accept the solutions you are attempting to impose.
in the united states, you have today created a law, the telecommunications reform act, which repudiates your own constitution and insults the dreams of jefferson, washington, mill, madison, detoqueville, and brandeis. these dreams must now be born anew in us.
you are terrified of your own children, since they are natives in a world where you will always be immigrants. because you fear them, you entrust your bureaucracies with the parental responsibilities you are too cowardly to confront yourselves. in our world, all the sentiments and expressions of humanity, from the debasing to the angelic, are parts of a seamless whole, the global conversation of bits. we cannot separate the air that chokes from the air upon which wings beat.
in china, germany, france, russia, singapore, italy and the united states, you are trying to ward off the virus of liberty by erecting guard posts at the frontiers of cyberspace. these may keep out the contagion for a small time, but they will not work in a world that will soon be blanketed in bit-bearing media.
your increasingly obsolete information industries would perpetuate themselves by proposing laws, in america and elsewhere, that claim to own speech itself throughout the world. these laws would declare ideas to be another industrial product, no more noble than pig iron. in our world, whatever the human mind may create can be reproduced and distributed infinitely at no cost. the global conveyance of thought no longer requires your factories to accomplish.
these increasingly hostile and colonial measures place us in the same position as those previous lovers of freedom and self-determination who had to reject the authorities of distant, uninformed powers. we must declare our virtual selves immune to your sovereignty, even as we continue to consent to your rule over our bodies. we will spread ourselves across the planet so that no one can arrest our thoughts.
we will create a civilization of the mind in cyberspace. may it be more humane and fair than the world your governments have made before.
flag is mrctf vigenere crypto crack man, please add underscore and curly braces.
```

vigenere解密后，flag已经出现了！



## 0x6 [BJDCTF2020]rsa_output

看题目应该是RSA题目，看看这次又是什么花样？

```python
{21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111,2767}

{21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111,3659}

message1=20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599

message2=11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227
```

看题目的样子，应该是考察共模攻击的题目，直接丢个共模攻击的脚本吧：

```python
import libnum
import gmpy2

def common_modulus(n,c1,c2,e1,e2):
    assert(libnum.gcd(e1,e2))
    _, s1 ,s2 = gmpy2.gcdext(e1,e2)
    if s1 &lt; 0:
        s1 = -s1
        c1 = gmpy2.invert(c1,n)
    elif s2 &lt; 0:
        s2 = -s2
        c2 = gmpy2.invert(c2,n)
    return pow(c1,s1,n) * pow(c2,s2,n) % n

n = 21058339337354287847534107544613605305015441090508924094198816691219103399526800112802416383088995253908857460266726925615826895303377801614829364034624475195859997943146305588315939130777450485196290766249612340054354622516207681542973756257677388091926549655162490873849955783768663029138647079874278240867932127196686258800146911620730706734103611833179733264096475286491988063990431085380499075005629807702406676707841324660971173253100956362528346684752959937473852630145893796056675793646430793578265418255919376323796044588559726703858429311784705245069845938316802681575653653770883615525735690306674635167111

e1 = 2767

e2 = 3659

c1=20152490165522401747723193966902181151098731763998057421967155300933719378216342043730801302534978403741086887969040721959533190058342762057359432663717825826365444996915469039056428416166173920958243044831404924113442512617599426876141184212121677500371236937127571802891321706587610393639446868836987170301813018218408886968263882123084155607494076330256934285171370758586535415136162861138898728910585138378884530819857478609791126971308624318454905992919405355751492789110009313138417265126117273710813843923143381276204802515910527468883224274829962479636527422350190210717694762908096944600267033351813929448599

c2=11298697323140988812057735324285908480504721454145796535014418738959035245600679947297874517818928181509081545027056523790022598233918011261011973196386395689371526774785582326121959186195586069851592467637819366624044133661016373360885158956955263645614345881350494012328275215821306955212788282617812686548883151066866149060363482958708364726982908798340182288702101023393839781427386537230459436512613047311585875068008210818996941460156589314135010438362447522428206884944952639826677247819066812706835773107059567082822312300721049827013660418610265189288840247186598145741724084351633508492707755206886202876227

if __name__ == "__main__":
    m = common_modulus(n,c1,c2,e1,e2)
    flag = libnum.n2s(m)
    print flag
```

运行脚本，得到flag：

```txt
BJD{r3a_C0mmoN_moD@_4ttack}
```



## 0x7 [MRCTF2020]keyboard

键盘密码吗？瞧瞧看吧！

```txt
得到的flag用
MRCTF{xxxxxx}形式上叫
都为小写字母

6
666
22
444
555
33
7
44
666
66
3
```

似曾相识的熟悉内容，用丢个脚本解决吧！

```python
keyborad = [None,None,"ABC","DEF","GHI","JKL","MNO","PQRS","TUV","WXYZ"]
c = "6 666 22 444 555 33 7 44 666 66 3"
c_list = c.split(" ")
m = ""
for i in c_list:
    m += keyborad[int(i[0])][len(i)-1]

print m
```

运行脚本，得到一个错误的flag：

```txt
MOBILEPHOND
```

需要进行简单拼写检查进行修改，便得到flag：

```txt
MOBILEPHONE
```



## 0x8 [BJDCTF2020]signin

签到题？萌新狂喜！看看是什么样的签到吧：

```txt
welcome to crypto world！！
密文：424a447b57653163306d655f74345f424a444354467d
```

看样子应该是一个HEX编码的密文，解一下就得到flag了：

```txt
BJD{We1c0me_t4_BJDCTF}
```



## 0x9 [ACTF新生赛2020]crypto-rsa0

RSA题目，题目内容应该是比较有意思的：

附件文件有两个文件，一个hint.txt应该是一个提示文件，还有一个压缩包，但是压缩包打不开，嘤嘤嘤~

看看hint.txt里面有什么：

```
怎么办呢，出题人也太坏了，竟然把压缩包给伪加密了！
```

感觉有点像是杂项题目……伪加密，那是什么东西？

菜狗查一查……

经过查询发现，好像是zip文件结构中的09标志着是伪加密文件结构，只需要将09修改为00就可以破解伪加密，可以使用一个010edit工具进行修改：

[![img](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-20.png)](/images/BUUCTF-CRYPTO-[49-64]_writeup/image-20.png)

然后将09修改成00并将文件进行保持即可进行解压操作

解压得到一个rsa0.py的python源码文件和一个output的文本文件

rsa0.py

```python
from Cryptodome.Util.number import *
import random

FLAG=#hidden, please solve it
flag=int.from_bytes(FLAG,byteorder = 'big')


p=getPrime(512)
q=getPrime(512)

print(p)
print(q)
N=p*q
e=65537
enc = pow(flag,e,N)
print (enc)
```

output

```txt
9018588066434206377240277162476739271386240173088676526295315163990968347022922841299128274551482926490908399237153883494964743436193853978459947060210411

7547005673877738257835729760037765213340036696350766324229143613179932145122130685778504062410137043635958208805698698169847293520149572605026492751740223

50996206925961019415256003394743594106061473865032792073035954925875056079762626648452348856255575840166640519334862690063949316515750256545937498213476286637455803452890781264446030732369871044870359838568618176586206041055000297981733272816089806014400846392307742065559331874972274844992047849472203390350
```

根据源代码，可以看出源码已经将p，q，c的数据输出，而且根据源码中的e的数值，写个简单脚本就可以解决了：

```python
import libnum

p = 9018588066434206377240277162476739271386240173088676526295315163990968347022922841299128274551482926490908399237153883494964743436193853978459947060210411
q = 7547005673877738257835729760037765213340036696350766324229143613179932145122130685778504062410137043635958208805698698169847293520149572605026492751740223
c = 50996206925961019415256003394743594106061473865032792073035954925875056079762626648452348856255575840166640519334862690063949316515750256545937498213476286637455803452890781264446030732369871044870359838568618176586206041055000297981733272816089806014400846392307742065559331874972274844992047849472203390350
e = 65537
n = p*q
phi = (p-1)*(q-1)
d = libnum.invmod(e,phi)
m = pow(c,d,n)
flag = libnum.n2s(m)
print flag
```

运行脚本，得到flag：

```txt
actf{n0w_y0u_see_RSA}
```



## 0xA 一张谍报

看样子，应该是一个古典密码学题目，或者脑洞题？

看一下题目描述：

```txt
国家能源总部经过派出卧底长期刺探，终于找到一个潜伏已久的国外内鬼：三楼能源楼管老王。由于抓捕仓促，老王服毒自尽了。侦查部门搜出老王每日看的报纸原来是特制的情报。聪明的你能从附件的报纸中找出情报么？flag是老王说的暗号。（由于老王的线人曾今做的土匪，所以用的行话） 注意：得到的 flag 请包上 flag{} 提交
```

附件文件是一个docx文件：

```txt
国家能源时报2015年3月5日
平时要针对性的吃些防辐射菜
对于和电脑“朝夕相处”的人们来说,辐射的确是个让人忧心的“副产物”。因此,平时针对性的吃些可以防辐射的菜是很有好处的。特别是现在接近年底，加班加点是家常便饭，对着电脑更是辐射吸收得满满的，唯有趁一日三餐进食的时候吃点防辐射的食物了。

朝歌区梆子公司三更放炮
老小区居民大爷联合抵制

今天上午，朝歌区梆子公司决定，在每天三更天不亮免费在各大小区门口设卡为全城提供二次震耳欲聋的敲更提醒，呼吁大家早睡早起，不要因为贪睡断送大好人生，时代的符号是前进。为此，全区老人都蹲在该公司东边树丛合力抵制，不给公司人员放行，场面混乱。李罗鹰住进朝歌区五十年了，人称老鹰头，几年孙子李虎南刚从东北当猎户回来，每月还寄回来几块鼹鼠干。李罗鹰当年遇到的老婆是朝歌一枝花，所以李南虎是长得非常秀气的一个汉子。李罗鹰表示：无论梆子公司做的对错，反正不能打扰他孙子睡觉，子曰：‘睡觉乃人之常情’。梆子公司这是连菩萨睡觉都不放过啊。李南虎表示：梆子公司智商捉急，小心居民猴急跳墙！这三伏天都不给睡觉，这不扯淡么！
到了中午人群仍未离散，更有人提议要烧掉这个公司，公司高层似乎恨不得找个洞钻进去。直到治安人员出现才疏散人群归家，但是李南虎仍旧表示爷爷年纪大了，睡不好对身体不好。
朝歌区梆子公司三更放炮
老小区居民大爷联合抵制
喵天上午，汪歌区哞叽公司决定，在每天八哇天不全免费在各大小区门脑设卡为全城提供双次震耳欲聋的敲哇提醒，呼吁大家早睡早起，不要因为贪睡断送大好人生，时代的编号是前进。为此，全区眠人都足在该公司流边草丛合力抵制，不给公司人员放行，场面混乱。李罗鸟住进汪歌区五十年了，人称眠鸟顶，几年孙叽李熬值刚从流北当屁户回来，每月还寄回来几块报信干。李罗鸟当年遇到的眠婆是汪歌一枝花，所以李值熬是长得非常秀气的一个汉叽。李罗鸟表示：无论哞叽公司做的对错，反正不能打扰他孙叽睡觉，叽叶：‘睡觉乃人之常情’。哞叽公司这是连衣服睡觉都不放过啊。李值熬表示：哞叽公司智商捉急，小心居民猴急跳墙！这八伏天都不给睡觉，这不扯淡么！
到了中午人群仍未离散，哇有人提议要烧掉这个公司，公司高层似乎恨不得找个洞钻进去。直到治安人员出现才疏散人群归家，但是李值熬仍旧表示爷爷年纪大了，睡不好对身体不好。

听书做作业

喵汪哞叽双哇顶，眠鸟足屁流脑，八哇报信断流脑全叽，眠鸟进北脑上草，八枝遇孙叽，孙叽对熬编叶：值天衣服放鸟捉猴顶。鸟对：北汪罗汉伏熬乱天门。合编放行，卡编扯呼。人离烧草，报信归洞，孙叽找爷爷。
```

这道题目其实更像是一道MISC题目，这道题目的总体思路是和达芬奇密码那道题目有着异曲同工之妙的，

写个处理脚本即可：

```python
flag = ""
flag_list = []
str1 = "今天上午，朝歌区梆子公司决定，在每天三更天不亮免费在各大小区门口设卡为全城提供二次震耳欲聋的敲更提醒，呼吁大家早睡早起，不要因为贪睡断送大好人生，时代的符号是前进。为此，全区老人都蹲在该公司东边树丛合力抵制，不给公司人员放行，场面混乱。李罗鹰住进朝歌区五十年了，人称老鹰头，几年孙子李虎南刚从东北当猎户回来，每月还寄回来几块鼹鼠干。李罗鹰当年遇到的老婆是朝歌一枝花，所以李南虎是长得非常秀气的一个汉子。李罗鹰表示：无论梆子公司做的对错，反正不能打扰他孙子睡觉，子曰：‘睡觉 乃人之常情’。梆子公司这是连菩萨睡觉都不放过啊。李南虎表示：梆子公司智商捉急，小心居民猴急跳墙！这三伏天都不给睡觉，这不 扯淡么！到了中午人群仍未离散，更有人提议要烧掉这个公司，公司高层似乎恨不得找个洞钻进去。直到治安人员出现才疏散人群归家，但是李南虎仍旧表示爷爷年纪大了，睡不好对身体不好。"
str2 = "喵天上午，汪歌区哞叽公司决定，在每天八哇天不全免费在各大小区门脑设卡为全城提供双次震耳欲聋的敲哇提醒，呼吁大家早睡早起，不要因为贪睡断送大好人生，时代的编号是前进。为此，全区眠人都足在该公司流边草丛合力抵制，不给公司人员放行，场面混乱。李罗鸟住进汪歌区五十年了，人称眠鸟顶，几年孙叽李熬值刚从流北当屁户回来，每月还寄回来几块报信干。李罗鸟当年遇到的眠婆是汪歌一枝花，所以李值熬是长得非常秀气的一个汉叽。李罗鸟表示：无论哞叽公司做的对错，反正不能打扰他孙叽睡觉，叽叶：‘睡觉 乃人之常情’。哞叽公司这是连衣服睡觉都不放过啊。李值熬表示：哞叽公司智商捉急，小心居民猴急跳墙！这八伏天都不给睡觉，这不 扯淡么！到了中午人群仍未离散，哇有人提议要烧掉这个公司，公司高层似乎恨不得找个洞钻进去。直到治安人员出现才疏散人群归家，但是李值熬仍旧表示爷爷年纪大了，睡不好对身体不好。"
str3 = "喵汪哞叽双哇顶，眠鸟足屁流脑，八哇报信断流脑全叽，眠鸟进北脑上草，八枝遇孙叽，孙叽对熬编叶：值天衣服放鸟捉猴顶。鸟对：北汪罗汉伏熬乱天门。合编放行，卡编扯呼。人离烧草，报信归洞，孙叽找爷爷。"

for i in range(len(str3)):
    for j in range(len(str2)):
        if str3[i] == str2[j]:
            flag += str1[j]
            break
print(flag)
```

运行脚本得到一段文字：

```txt
今朝梆子二更头，老鹰蹲猎东口，三更鼹鼠断东口亮子，老鹰进北口上树，三枝遇孙子，孙子对虎符曰：南天菩萨放鹰捉猴头。鹰对：北朝罗汉伏虎乱天门。合符放行，卡符扯呼。人离烧树，鼹鼠归洞，孙子找爷爷。
```

而本题的flag就在这段文字中，即flag{南天菩萨放鹰捉猴头}



## 0xB SameMod

看到题目，不由就联想到了共模攻击，应该是一道RSA题目，瞧瞧看吧！

```python
{6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249,773}
{6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249,839}

message1=3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349
message2=5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535
```

这熟悉的感觉，共模攻击没错了！

直接丢个共模攻击的脚本：

```python
import libnum
n = 6266565720726907265997241358331585417095726146341989755538017122981360742813498401533594757088796536341941659691259323065631249
e1 = 773
e2 = 839

c1=3453520592723443935451151545245025864232388871721682326408915024349804062041976702364728660682912396903968193981131553111537349
c2=5672818026816293344070119332536629619457163570036305296869053532293105379690793386019065754465292867769521736414170803238309535
def Samemod(n,c1,c2,e1,e2):
    def egcd(a,b):
        if b == 0:
            return a,0
        else:
            x,y = egcd(b, a % b)
            return y,x - ( a//b )*y
    s = egcd(e1,e2)
    s1 = s[0]
    s2 = s[1]
    if s1&lt;0:
        s1 = -s1
        c1 = libnum.invmod(c1,n)
    elif s2&lt;0:
        s2 = -s2
        c2 = libnum.invmod(c2,n)
    m = pow(c1,s1,n)*pow(c2,s2,n) %n
    return m

m = Samemod(n, c1, c2, e1, e2)
flag = ""
m = str(m)
i = 0
while i&lt;len(m):
    if m[i] == '1':
        c = chr(int(m[i:i+3]))
        i += 3
    else:
        c=chr(int(m[i:i+2]))
        i += 2
    flag +=c
print flag
```

运行脚本，得到flag：

```txt
flag{whenwethinkitispossible}
```



## 0xC [GWCTF 2019]BabyRSA

开始了，开始了！RSA的盛宴！

两个文件，一个secret文件，一个encrypt.py文件

secret

```python
N=636585149594574746909030160182690866222909256464847291783000651837227921337237899651287943597773270944384034858925295744880727101606841413640006527614873110651410155893776548737823152943797884729130149758279127430044739254000426610922834573094957082589539445610828279428814524313491262061930512829074466232633130599104490893572093943832740301809630847541592548921200288222432789208650949937638303429456468889100192613859073752923812454212239908948930178355331390933536771065791817643978763045030833712326162883810638120029378337092938662174119747687899484603628344079493556601422498405360731958162719296160584042671057160241284852522913676264596201906163
m1=90009974341452243216986938028371257528604943208941176518717463554774967878152694586469377765296113165659498726012712288670458884373971419842750929287658640266219686646956929872115782173093979742958745121671928568709468526098715927189829600497283118051641107305128852697032053368115181216069626606165503465125725204875578701237789292966211824002761481815276666236869005129138862782476859103086726091860497614883282949955023222414333243193268564781621699870412557822404381213804026685831221430728290755597819259339616650158674713248841654338515199405532003173732520457813901170264713085107077001478083341339002069870585378257051150217511755761491021553239
m2=487443985757405173426628188375657117604235507936967522993257972108872283698305238454465723214226871414276788912058186197039821242912736742824080627680971802511206914394672159240206910735850651999316100014691067295708138639363203596244693995562780286637116394738250774129759021080197323724805414668042318806010652814405078769738548913675466181551005527065309515364950610137206393257148357659666687091662749848560225453826362271704292692847596339533229088038820532086109421158575841077601268713175097874083536249006018948789413238783922845633494023608865256071962856581229890043896939025613600564283391329331452199062858930374565991634191495137939574539546
```

encrypt.py

```python
import hashlib
import sympy
from Crypto.Util.number import *

flag = 'GWHT{******}'
secret = '******'

assert(len(flag) == 38)

half = len(flag) / 2

flag1 = flag[:half]
flag2 = flag[half:]

secret_num = getPrime(1024) * bytes_to_long(secret)

p = sympy.nextprime(secret_num)
q = sympy.nextprime(p)

N = p * q

e = 0x10001

F1 = bytes_to_long(flag1)
F2 = bytes_to_long(flag2)

c1 = F1 + F2
c2 = pow(F1, 3) + pow(F2, 3)
assert(c2 &lt; N)

m1 = pow(c1, e, N)
m2 = pow(c2, e, N)

output = open('secret', 'w')
output.write('N=' + str(N) + 'n')
output.write('m1=' + str(m1) + 'n')
output.write('m2=' + str(m2) + 'n')
output.close()
```

根据源码文件，可以对源码文件进行简单分析，发现p和q的数值是非常接近的，可以直接对n开平方然后求得下一个素数来得到p，然后再用n除以p来得到q。这道rsa题目使用了套娃，对密文加了一层方程组的套套：

\[   c_1 = F_1+F_2  \]

\[ c_2 = F_1^3 + F_2^3  \]

其实这道题目也没有太大的难度，扔给脚本直接求解就好：

```python
import libnum
import sympy

N=636585149594574746909030160182690866222909256464847291783000651837227921337237899651287943597773270944384034858925295744880727101606841413640006527614873110651410155893776548737823152943797884729130149758279127430044739254000426610922834573094957082589539445610828279428814524313491262061930512829074466232633130599104490893572093943832740301809630847541592548921200288222432789208650949937638303429456468889100192613859073752923812454212239908948930178355331390933536771065791817643978763045030833712326162883810638120029378337092938662174119747687899484603628344079493556601422498405360731958162719296160584042671057160241284852522913676264596201906163
m1=90009974341452243216986938028371257528604943208941176518717463554774967878152694586469377765296113165659498726012712288670458884373971419842750929287658640266219686646956929872115782173093979742958745121671928568709468526098715927189829600497283118051641107305128852697032053368115181216069626606165503465125725204875578701237789292966211824002761481815276666236869005129138862782476859103086726091860497614883282949955023222414333243193268564781621699870412557822404381213804026685831221430728290755597819259339616650158674713248841654338515199405532003173732520457813901170264713085107077001478083341339002069870585378257051150217511755761491021553239
m2=487443985757405173426628188375657117604235507936967522993257972108872283698305238454465723214226871414276788912058186197039821242912736742824080627680971802511206914394672159240206910735850651999316100014691067295708138639363203596244693995562780286637116394738250774129759021080197323724805414668042318806010652814405078769738548913675466181551005527065309515364950610137206393257148357659666687091662749848560225453826362271704292692847596339533229088038820532086109421158575841077601268713175097874083536249006018948789413238783922845633494023608865256071962856581229890043896939025613600564283391329331452199062858930374565991634191495137939574539546
e = 0x10001

p =sympy.nextprime(libnum.nroot(N,2))
q = N // p

assert(N == p*q)

phi = (p-1)*(q-1)
d = libnum.invmod(e,phi)
c1 = pow(m1,d,N)
c2 = pow(m2,d,N)

x = sympy.Symbol('x')
y = sympy.Symbol('y')
result = sympy.solve([x + y - c1, x**3 + y**3 - c2 ],[x,y])
# print result
F1 = int(result[0][0])
F2 = int(result[0][1])

flag1 = libnum.n2s(F1)
flag2 = libnum.n2s(F2)
flag = flag2 + flag1
print flag
```

运行脚本，大约等个2min，得到flag：

```txt
GWHT{f709e0e2cfe7e530ca8972959a1033b2}
```



## 0xD [WUSTCTF2020]babyrsa

又是一道有点意思的RSA题目，看看题吧！

```python
c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537
```

拿到这个题目，好像除了爆破n，没有什么别的方法了，那就分解一下n就好了

使用sage分解一下（笑~漫长的等待）,得到分解结果：

```txt
189239861511125143212536989589123569301*386123125371923651191219869811293586459
```

然后就是愉快地写脚本了：

```python
import libnum

c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537
p = 189239861511125143212536989589123569301
q = 386123125371923651191219869811293586459
phi = (p-1)*(q-1)

d = libnum.invmod(e,phi)
m = pow(c,d,n)

flag = libnum.n2s(m)

print flag
```

运行脚本，得到flag：

```txt
wctf2020{just_@_piece_0f_cak3}
```



## 0xE RSA4

看看这RSA有什么东西吧！

```python
N = 331310324212000030020214312244232222400142410423413104441140203003243002104333214202031202212403400220031202142322434104143104244241214204444443323000244130122022422310201104411044030113302323014101331214303223312402430402404413033243132101010422240133122211400434023222214231402403403200012221023341333340042343122302113410210110221233241303024431330001303404020104442443120130000334110042432010203401440404010003442001223042211442001413004 
c = 310020004234033304244200421414413320341301002123030311202340222410301423440312412440240244110200112141140201224032402232131204213012303204422003300004011434102141321223311243242010014140422411342304322201241112402132203101131221223004022003120002110230023341143201404311340311134230140231412201333333142402423134333211302102413111111424430032440123340034044314223400401224111323000242234420441240411021023100222003123214343030122032301042243

N = 302240000040421410144422133334143140011011044322223144412002220243001141141114123223331331304421113021231204322233120121444434210041232214144413244434424302311222143224402302432102242132244032010020113224011121043232143221203424243134044314022212024343100042342002432331144300214212414033414120004344211330224020301223033334324244031204240122301242232011303211220044222411134403012132420311110302442344021122101224411230002203344140143044114 
c = 112200203404013430330214124004404423210041321043000303233141423344144222343401042200334033203124030011440014210112103234440312134032123400444344144233020130110134042102220302002413321102022414130443041144240310121020100310104334204234412411424420321211112232031121330310333414423433343322024400121200333330432223421433344122023012440013041401423202210124024431040013414313121123433424113113414422043330422002314144111134142044333404112240344

N = 332200324410041111434222123043121331442103233332422341041340412034230003314420311333101344231212130200312041044324431141033004333110021013020140020011222012300020041342040004002220210223122111314112124333211132230332124022423141214031303144444134403024420111423244424030030003340213032121303213343020401304243330001314023030121034113334404440421242240113103203013341231330004332040302440011324004130324034323430143102401440130242321424020323 
c = 10013444120141130322433204124002242224332334011124210012440241402342100410331131441303242011002101323040403311120421304422222200324402244243322422444414043342130111111330022213203030324422101133032212042042243101434342203204121042113212104212423330331134311311114143200011240002111312122234340003403312040401043021433112031334324322123304112340014030132021432101130211241134422413442312013042141212003102211300321404043012124332013240431242
```

看样子是低加密指数广播攻击了，观察数据发现数据中都是小于5的数字，五进制，这可太恶心了，看来还需要进行一下进制转换。但是题目没有给出e的数值，根据这种攻击可能的情况，e的取值是3，10，17，然后结合中国剩余定理求解，我丢！

```python
import libnum
import string
N1 = 331310324212000030020214312244232222400142410423413104441140203003243002104333214202031202212403400220031202142322434104143104244241214204444443323000244130122022422310201104411044030113302323014101331214303223312402430402404413033243132101010422240133122211400434023222214231402403403200012221023341333340042343122302113410210110221233241303024431330001303404020104442443120130000334110042432010203401440404010003442001223042211442001413004
c1 = 310020004234033304244200421414413320341301002123030311202340222410301423440312412440240244110200112141140201224032402232131204213012303204422003300004011434102141321223311243242010014140422411342304322201241112402132203101131221223004022003120002110230023341143201404311340311134230140231412201333333142402423134333211302102413111111424430032440123340034044314223400401224111323000242234420441240411021023100222003123214343030122032301042243

N2 = 302240000040421410144422133334143140011011044322223144412002220243001141141114123223331331304421113021231204322233120121444434210041232214144413244434424302311222143224402302432102242132244032010020113224011121043232143221203424243134044314022212024343100042342002432331144300214212414033414120004344211330224020301223033334324244031204240122301242232011303211220044222411134403012132420311110302442344021122101224411230002203344140143044114
c2 = 112200203404013430330214124004404423210041321043000303233141423344144222343401042200334033203124030011440014210112103234440312134032123400444344144233020130110134042102220302002413321102022414130443041144240310121020100310104334204234412411424420321211112232031121330310333414423433343322024400121200333330432223421433344122023012440013041401423202210124024431040013414313121123433424113113414422043330422002314144111134142044333404112240344

N3 = 332200324410041111434222123043121331442103233332422341041340412034230003314420311333101344231212130200312041044324431141033004333110021013020140020011222012300020041342040004002220210223122111314112124333211132230332124022423141214031303144444134403024420111423244424030030003340213032121303213343020401304243330001314023030121034113334404440421242240113103203013341231330004332040302440011324004130324034323430143102401440130242321424020323
c3 = 10013444120141130322433204124002242224332334011124210012440241402342100410331131441303242011002101323040403311120421304422222200324402244243322422444414043342130111111330022213203030324422101133032212042042243101434342203204121042113212104212423330331134311311114143200011240002111312122234340003403312040401043021433112031334324322123304112340014030132021432101130211241134422413442312013042141212003102211300321404043012124332013240431242
N = [N1,N2,N3]
c = [c1,c2,c3]

for i in range(3):
    N[i] = int(str(N[i]),5)
    c[i] = int(str(c[i]),5)

def CRT(data):
    sum_ = 0
    m = 1
    for n in data:
        m = m*n[0]
    for n,c in data:
        m1 = m/n
        mr = libnum.invmod(m1,n)
        sum_ = sum_ + mr * m1 * c

    return sum_ % m

def isprintstr(data):
    index = 0
    for i in data:
        if i not in string.printable:
            index = 0
            break
        else:
            index = 1
    if index == 1:
        return libnum.n2s(m)
    else:
        return False


data = zip(N,c)
m_e = CRT(data)

e = [3,10,17]
flag = ""
for i in e:
    m = libnum.nroot(m_e,i)
    flag = isprintstr(libnum.n2s(m))
    if flag:
        print flag
```

运行脚本，得到flag：

```txt
noxCTF{D4mn_y0u_h4s74d_wh47_4_b100dy_b4s74rd!}
```



## 0xF yxx

这是啥？看看题目吧！

附件里面是两个txt文件

明文.txt：

```txt
lovelovelovelovelovelovelovelove
```

密文.txt：

```txt
V

0
0
0

```

密文中有很多不可打印的字符，这道题目应该是考察异或操作的，写个脚本读一下转一下数字进行一下异或：

```python
import libnum
c = ""
m = ""
with open("c.txt","rb") as f:
    lines = f.readlines()
    for line in lines:
        c += line

with open("m.txt") as f:
    lines = f.readlines()
    for line in lines:
        m += line

m_n = libnum.s2n(m)
c_n = libnum.s2n(c)
result = m_n^c_n
flag = libnum.n2s(result)

print flag
```

运行脚本，得到flag：

```txt
flag:nctf{xor_xor_xor_biubiubiu}
```



本期wp分享到此为止，有时间再来喝杯茶呀！
