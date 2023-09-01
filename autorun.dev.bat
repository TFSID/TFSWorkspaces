@echo off
set program_path1="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
set parameters1=ssh tfs@172.16.1.20

# set program_path2="C:\Program Files\Wireshark\Wireshark.exe"
# set parameters2=


REM Execute program 1
start "" %program_path1% %parameters1%

# REM Execute program 2
# start "" %program_path2% 



