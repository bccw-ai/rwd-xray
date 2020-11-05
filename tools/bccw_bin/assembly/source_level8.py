import base64

print('计算第8关密钥中,时间可能非常长...')
b = 10
stack = []
ins_len = [1] * 5 + [2] * 9 + [9, 1]
reg = [0] * 16
code = base64.b64decode('zyLpMs8CL9Oy/3QDdRlURZRGFHQHdRhURZFGIL/lv+MiNi+70AXRBtMD1wfYCNkJ5v3/iV14RWMB0n+/xgk=')

def Decrypt(key:str, text:str) -> str:
  if len(key) < 32: key += ' ' * (32 - len(key))
  elif len(key) > 32: key = key[0:32]
  cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
  return str(gzip.decompress(bytes.strip(cipher.decrypt(base64.b64decode(text)))), encoding='utf-8')


def Pass(id, priv_key):
  prefix = str(id) + str(int(time.time()))
  pub_key = prefix + md5(bytes(prefix + priv_key, 'utf8')).hexdigest()
  print('恭喜通过第%d关,通关公钥:%s' % (id, pub_key))


while b:
        ins, r0 = code[reg[15]] >> 4, code[reg[15]] & 15
        length = ins_len[ins]
        if length > 1:
                arg = code[reg[15] + 1 : reg[15] + length]
                if length == 2: r1 = arg[0] >> 4; r2 = arg[0] & 15
        reg[15] += length
        if 0 == ins : break
        elif 1 == ins : stack.append(reg[r0]); print("ins:", ins)
        elif 2 == ins : reg[r0] = stack.pop(); print("ins:", ins)
        elif 3 == ins : 
                if not reg[r0] : reg[15] += ins_len[code[reg[15]] >> 4]; print("ins:", ins)
        elif 4 == ins : reg[r0] = 0 if reg[r0] else 1; print("ins:", ins)
        elif 5 == ins : reg[r0] = reg[r1] + reg[r2]; print("ins+:", ins)
        elif 6 == ins : reg[r0] = reg[r1] - reg[r2]; print("ins-:", ins)
        elif 7 == ins : reg[r0] = reg[r1] * reg[r2]; print("ins*:", ins)
        elif 8 == ins : reg[r0] = reg[r1] / reg[r2]; print("ins/:", ins)
        elif 9 == ins : reg[r0] = reg[r1] % reg[r2]; print("ins%:", ins)
        elif 10 == ins : reg[r0] = 1 if reg[r1] < reg[r2] else 0; print("ins:", ins)
        elif 11 == ins : stack.append(reg[r0]); reg[r0] += int.from_bytes(arg, byteorder='little', signed=True); print("ins:", ins)
        elif 12 == ins : reg[r0] += int.from_bytes(arg, byteorder='little', signed=True); print("ins:", ins)
        elif ins in (13, 14) : reg[r0] = int.from_bytes(arg, byteorder='little', signed=True); print("ins:", ins)
        print("ins:", ins)
        print("stack:", stack)
        print(">寄存器reg:", reg)
        print()
        b -= 1
        if 10 <= b: break

#key = str(reg[0])+str(reg[1])
#key = 3298258025528854553625821261494113
#exec(Decrypt(key,'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'))
