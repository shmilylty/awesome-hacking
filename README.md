# 超棒黑客必备表单 [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

[English Version](https://github.com/carpedm20/awesome-hacking)

一份精美的黑客必备表单,灵感来自于[超棒的机器学习](https://github.com/josephmisiti/awesome-machine-learning/)，如果您想为此列表做出贡献（欢迎），请在github给我一个pull或联系我[@carpedm20](https://twitter.com/carpedm20)，有关可供下载的免费黑客书籍列表，请点击[此处](https://github.com/Hack-with-Github/Free-Security-eBooks)。


## 目录

<!-- MarkdownTOC depth=4 -->

- [系统方面](#系统方面)
    - [教程](#教程)
    - [工具](#工具)
    - [Docker](#docker)
    - [常用](#常用)
- [逆向方面](#逆向方面)
    - [教程](#教程)
    - [工具](#工具)
    - [常用](#常用)
- [Web方面](#web)
    - [教程](#教程)
    - [工具](#工具)
- [网络方面](#网络方面)
    - [教程](#教程)
    - [工具](#工具)
- [取证方面](#取证方面)
    - [教程](#教程)
    - [工具](#工具)
- [密码方面](#密码方面)
    - [教程](#教程)
    - [工具](#工具)
- [Wargame方面](#wargame方面)
    - [系统](#系统)
    - [逆向工程](#逆向工程)
    - [Web](#web)
    - [网络](#网络)
    - [取证](#取证)
    - [密码学](#密码学)
- [CTF方面](#ctf)
    - [比赛](#比赛)
    - [常用](#常用)
- [OS安全方面](#os安全方面)
    - [在线资源](#在线资源)
- [其他](#其他)

<!-- /MarkdownTOC -->

# 系统方面

## 教程
 * [Corelan团队的Exploit写作教程](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
 * [为渗透测试员开发的Exploit写作教程](http://www.punter-infosec.com/exploit-writing-tutorials-for-pentesters/)

## 工具
 * [Metasploit](https://github.com/rapid7/metasploit-framework) - 一个计算机安全项目，提供有关安全漏洞的信息，并帮助进行渗透测试和入侵检测系统开发。
 * [mimikatz](https://github.com/gentilkiwi/mimikatz) - 一个玩Windows安全有用的工具

### 有关渗透测试和安全方面的Docker镜像
 * `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
 * `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
 * `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
 * `docker pull pandrew/metasploit` - [docker-metasploit](https://hub.docker.com/r/pandrew/metasploit/)
 * `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
 * `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
 * `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
 * `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
 * `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
 * `docker pull usertaken/archlinux-pentest-lxde` - [Arch Linux Penetration Tester](https://hub.docker.com/r/usertaken/archlinux-pentest-lxde/)
 * `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
 * `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
 * `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
 * `docker-compose build && docker-compose up` - [OWASP NodeGoat](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker)
 * `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)
 * `docker pull bkimminich/juice-shop` - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop#docker-container--)

## 常用
 * [Exploit database](https://www.exploit-db.com/) - 漏洞利用和易受攻击软件的终极存档库


# 逆向方面

## 教程

* [逆转新手](https://tuts4you.com/download.php?list.17)
* [恶意软件分析教程：逆向工程](http://fumalwareanalysis.blogspot.kr/p/malware-analysis-tutorials-reverse.html)

## 工具
 * [nudge4j](https://github.com/lorenzoongithub/nudge4j) - 让浏览器与JVM交互的Java工具
 * [IDA](https://www.hex-rays.com/products/ida/) - IDA是可以工作在Windows，Linux或Mac OS X的多处理反汇编和调试工具
 * [OllyDbg](http://www.ollydbg.de/) - Windows 32位汇编程序级别调试工具
 * [x64dbg](http://x64dbg.com/) - Windows上开源x64/x32调试工具
 * [dex2jar](https://github.com/pxb1988/dex2jar) - 用于处理用于处理Android .dex和Java .class文件的工具
 * [JD-GUI](http://jd.benow.ca/) - 显示Java源代码“.class”文件的独立图形实用工具
 * [procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - 现代化开源Java反编译工具
 * [androguard](https://code.google.com/p/androguard/) - 用于Android应用程序的逆向工程，恶意软件分析工具
 * [JAD](http://varaneckas.com/jad/) - JAD Java反编译工具(闭源, 不常更新)
 * [dotPeek](https://www.jetbrains.com/decompiler/) - JetBrains公司开发的免费的.NET反编译工具
 * [ILSpy](https://github.com/icsharpcode/ILSpy/) - 开源的集浏览和反编译.NET程序工具
 * [dnSpy](https://github.com/0xd4d/dnSpy) - 集编辑，反编译和调试.NET程序工具
 * [de4dot](https://github.com/0xd4d/de4dot) - 破解.NET程序工具
 * [antinet](https://github.com/0xd4d/antinet) - 用于反编译和混淆代码的.NET程序工具
 * [UPX](http://upx.sourceforge.net/) - 终极封装可执行文件工具
 * [radare2](https://github.com/radare/radare2) - 便携式的逆向工程框架工具
 * [plasma](https://github.com/joelpx/plasma) - 适用于x86/ARM/MIPS交互式反汇编，使用花指令语法代码生成伪代码。
 * [Hopper](https://www.hopperapp.com) - 适用于OS X和Linux反汇编/反编译32/64位Windows/MAC/LINUX/iOS的可执行文件工具
 * [ScratchABit](https://github.com/pfalcon/ScratchABit) - 使用IDAPython兼容插件API轻松重新定位和可攻击的交互式反汇编工具



## 常用
 * [开放的恶意软件查询](http://www.offensivecomputing.net/)


# Web方面

## 工具
 * [sqlmap](https://github.com/sqlmapproject/sqlmap) - 自动SQL注入和数据库入侵工具
 * [tools.web-max.ca](http://tools.web-max.ca/encode_decode.php) - base64，base85编码/解码


# 网络方面

## 工具
 * [Wireshark](https://www.wireshark.org/) - 免费开源的流量包分析工具
 * [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - 网络取证分析工具
 * [tcpdump](http://www.tcpdump.org/) - 功能强大的命令行流量包分析工具，自带的libpcap用于网络流量捕获的便携式C/C++库
 * [Paros](http://sourceforge.net/projects/paros/) - 基于Java的HTTP/HTTPS代理用于评估Web应用程序漏洞工具
 * [pig](https://github.com/rafael-santiago/pig) - Linux下伪造流量包工具
 * [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - ZAP是用于发现Web应用程序中漏洞易于使用的集成式渗透测试工具
 * [mitmproxy](https://mitmproxy.org/) - 基于HTTP具有交互式控制界面并支持SSL中间代理的工具
 * [mitmsocks4j](https://github.com/Akdeniz/mitmsocks4j) - 基于Java支持中间SOCKS代理工具
 * [nmap](https://nmap.org/) - Nmap安全扫描工具
 * [Aircrack-ng](http://www.aircrack-ng.org/) - 用于破解802.11 WEP和WPA-PSK密钥工具
 * [Charles Proxy](https://charlesproxy.com) - 用于查看截获的HTTP和HTTPS/SSL实时流量的跨平台图形化用户界面Web调试代理工具
 * [Nipe](https://github.com/GouveaHeitor/nipe) - 使Tor网络成为默认网关的脚本


# 取证方面

## 工具
 * [Autospy](http://www.sleuthkit.org/autopsy/) - 数字取证平台，[The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/index.php)的图形界面，还包含其他数字取证工具。
 * [sleuthkit](https://github.com/sleuthkit/sleuthkit) - 收集各种命令行数字取证工具库
 * [EnCase](https://www.guidancesoftware.com/products/Pages/encase-forensic/overview.aspx) - Guidance Software开发的一套使用共享技术数字取证工具
 * [malzilla](http://malzilla.sourceforge.net/) - 恶意软件抓捕工具
 * [PEview](http://wjradburn.com/software/) - 快速简便查看程序结构和32位可移植可执行文件（PE）以及组件对象文件格式（COFF）文件的内容
 * [HxD](http://mh-nexus.de/en/hxd/) - 十六进制编辑器，除了主存储器（RAM）的原始磁盘编辑和修改之外，可以处理任何大小的文件。
 * [WinHex](http://www.winhex.com/winhex/) - 十六进制编辑器，有助于计算机取证，数据恢复，低级数据处理和IT安全领域。
 * [BinText](http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx) - 一个小而快强大的文本提取器，程序员特别感兴趣。


# 密码方面

### 工具
 * [xortool](https://github.com/hellman/xortool) - 一种分析多字节XOR密码工具
 * [John the Ripper](http://www.openwall.com/john/) - 快速密码破解工具
 * [Aircrack](http://www.aircrack-ng.org/) - 802.11 WEP和WPA-PSK密钥破解工具


# Wargame方面

## 系统
 * [OverTheWire - Semtex](http://overthewire.org/wargames/semtex/)
 * [OverTheWire - Vortex](http://overthewire.org/wargames/vortex/)
 * [OverTheWire - Drifter](http://overthewire.org/wargames/drifter/)
 * [pwnable.kr](http://pwnable.kr/) - 提供有关系统安全性的各种pwn挑战
 * [Exploit Exercises - Nebula](https://exploit-exercises.com/nebula/)
 * [SmashTheStack](http://smashthestack.org/)

## 逆向工程
 * [Reversing.kr](http://www.reversing.kr/)
 * [CodeEngn](http://codeengn.com/challenges/)
 * [simples.kr](http://simples.kr/)
 * [Crackmes.de](http://crackmes.de/)

## Web
 * [Hack This Site!](https://www.hackthissite.org/)
 * [Webhacking.kr](http://webhacking.kr/)
 * [0xf.at](https://0xf.at/)


## 密码
 * [OverTheWire - Krypton](http://overthewire.org/wargames/krypton/)


# CTF方面

## 比赛
 * [DEF CON](https://legitbs.net/)
 * [CSAW CTF](https://ctf.isis.poly.edu/)
 * [hack.lu CTF](http://hack.lu/)
 * [Pliad CTF](http://www.plaidctf.com/)
 * [RuCTFe](http://ructf.org/e/)
 * [Ghost in the Shellcode](http://ghostintheshellcode.com/)
 * [PHD CTF](http://www.phdays.com/)
 * [SECUINSIDE CTF](http://secuinside.com/)
 * [Codegate CTF](http://ctf.codegate.org/html/Main.html?lang=eng)
 * [Boston Key Party CTF](http://bostonkeyparty.net/)
 * [HackTheBox](https://www.hackthebox.eu/)

## 常用
 * [CTFtime.org](https://ctftime.org/)
 * [WeChall](http://www.wechall.net/)
 * [CTF archives (shell-storm)](http://shell-storm.org/repo/CTF/)
 * [Rookit Arsenal](https://amzn.com/144962636X)
 * [Pentest Cheat Sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) - 渗透测试方面的干货
 * [Movies For Hacker](https://github.com/k4m4/movies-for-hackers) - 每个黑客必须看的电影清单

# OS安全方面

## 在线资源
 * [Security related Operating Systems @ Rawsec](http://rawsec.ml/en/security-related-os/) - 完整的有关操作系统安全表单
 * [Best Linux Penetration Testing Distributions @ CyberPunk](https://n0where.net/best-linux-penetration-testing-distributions/) - 渗透测试分工说明
 * [Security @ Distrowatch](http://distrowatch.com/search.php?category=Security) - 致力于讨论，审核和保持更新开源操作系统的网站

# 其他
 * [SecTools](http://sectools.org/) - 前125名网络安全工具
