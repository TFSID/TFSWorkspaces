@echo off
set program_path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
set parameters=suricata -c 'C:\Program Files\Suricata\suricata.yaml' -s signature.rules -i 172.16.1.150
%program_path% %parameters%

pause
