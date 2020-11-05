cf  0  2 12 jmp    off_36
22
e9
32  1  3 if (reg_2  == 0) : reg_15 += nextsize
cf  2 12 jmp    off_8
02
2f  1  2 reg_15  = pop()
d3
b2  2 11 push reg_2 ; reg_2  += -1     ; 第一层循环 入栈: 将 循环寄存器reg_2中的 数据 送入栈中(栈: 后进先出的方式访问内存空间)
ff
74  10  2  7 reg_4   = reg_0 *reg_3
03
75  12  2  7 reg_5   = reg_1 *reg_9
19
54  14  2  5 reg_4   = reg_4 +reg_5
45
94  16  2  9 reg_4   = reg_4 %reg_6
46
14  18  1  1 push reg_4                ; 第二层循环 入栈: 将 循环寄存器reg_4中的 数据 送入栈中(栈：CPU将一段内存当做栈来使用); 
74  19  2  7 reg_4   = reg_0 *reg_7
07
75  21  2  7 reg_5   = reg_1 *reg_8
18
54  23  2  5 reg_4   = reg_4 +reg_5
45
91  25  2  9 reg_1   = reg_4 %reg_6
46  
20  27  1  2 reg_0   = pop()           ; 从栈顶取出数据送入 reg_0 中
bf  28  2 11 push reg_15; reg_15 += -27
e5
bf  30  2 11 push reg_15; reg_15 += -29
e3
22  32  1  2 reg_2   = pop()           ; 从栈顶取出数据送入 reg_2 中
36  33  1  3 if (reg_6  == 0) : reg_15 += nextsize
2f  34  1  2 reg_15  = pop()
bb
d0  36  2 13 reg_0   = 5
05
d1  38  2 13 reg_1   = 6
06
d3  40  2 13 reg_3   = 3
03
d7  42  2 13 reg_7   = 7
07
d8  44  2 13 reg_8   = 8
08
d9  46  2 13 reg_9   = 9
09
e6  48  9 14 reg_6   = 99999999999999997
fd
ff
89
5d
78
45
63
01
d2  57  2 13 reg_2   = 127
7f
bf  59  2 11 push reg_15; reg_15 += -58  # the real exit
c6
09  61  1  0 exit