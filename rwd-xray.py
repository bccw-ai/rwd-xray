#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import os
import sys
import struct
import gzip
import binascii
import operator
import itertools
import importlib

def get_checksum(data):
    result = -sum(map(ord, data))
    return chr(result & 0xFF)

def write_firmware(data, file_name):
    with open(file_name, 'wb') as o:
        o.write(data)
    print('firmware: {}'.format(file_name))

def read_file(fn):
    # os.path.splitext(“文件路径”) 分离文件名与扩展名；默认返回(fname,f_extension)元组，可做分片操作
    f_name, f_ext     = os.path.splitext(fn)
    f_base            = os.path.basename(f_name)
    open_fn = open    # gzip.open or ?
    if f_ext == ".gz":
        # 写文件 f_out = gzip.open("xxx.gz", "wb")
        # 读文件 f_in  = gzip.open("xxx.gz", "rb")
        open_fn       = gzip.open
        f_name, f_ext = os.path.splitext(f_name)

    with open_fn(fn, 'rb') as f:
        f_data        = f.read()
    
    return f_data

# 获取零件编号前缀
def get_part_number_prefix(fn, short=False):
    f_name, f_ext = os.path.splitext(fn)
    f_base        = os.path.basename(f_name)
    # replace() 方法把字符串中的 old（旧字符串） 替换成 new(新字符串)，如果指定第三个参数max，则替换不超过 max 次。
    part_num      = f_base.replace('-','').replace('_', '')
    prefix = part_num[0:5] + '-' + part_num[5:8]
    if not short:
        prefix   += '-' + part_num[8:12]
    return prefix

def main():
    # sys.argv[]是用来获取命令行参数的，sys.argv[0]表示代码本身文件路径，所以参数从1开始
    f_name   = sys.argv[1]
    print("f_name = {}".format(f_name))
    f_dir    = os.path.dirname(f_name)  # 去掉文件名，返回目录
    # 3999-TAX-XXX.bin => split('.')[0]表示把指定的字符串按照"."来拆分成字符串数组.结果是：{a,b,c,d}
    f_base   = os.path.basename(f_name).split('.')[0]  # basename()返回path最后的文件名
    f_raw    = read_file(f_name)                       # 获取固件的原始数据
    f_type   = "x" + binascii.b2a_hex(f_raw[0])        # 把 固件 转换成二进制数据然后再用十六进制表示
    # 一个函数运行需要根据不同项目的配置，动态导入对应的配置文件运行。importlib允许程序员创建他们自定义的对象，可用于引入过程（也称为importer）。
    # importlib.import_module('b.c.c') # 绝对导入
    # importlib.import_module('.c.c',package='b') # 相对导入
    f_module = importlib.import_module("format.{}".format(f_type))
    # getattr(对象，对象属性) 函数用于返回一个对象属性值。
    f_class  = getattr(f_module, f_type)
    fw       = f_class(f_raw)
    print("fw = {}".format(fw))

    # write out encrypted firmware 写出加密固件
    fenc_name = os.path.join(f_dir, f_base + '.enc')
    with open(fenc_name, 'wb+') as fenc:
        for fe in fw.firmware_encrypted:
            fenc.write(fe)

    # attempt to decrypt firmware (validate by searching for part number in decrypted bytes)
    # 尝试解密固件（通过搜索解密字节中的部件号进行验证）
    part_number_prefix = get_part_number_prefix(f_name)   # 零件编号前缀
    print("part_number_prefix = {}".format(part_number_prefix))
    firmware_candidates = fw.decrypt(part_number_prefix)  # 候选固件
    if len(firmware_candidates) == 0:
        # try with a shorter part number 尝试使用较短的零件号
        print('failed on long part number, trying truncated part number ...')  # 长零件号失败，尝试截断零件号...
        part_number_prefix = get_part_number_prefix(f_name, short=True)
        firmware_candidates = fw.decrypt(part_number_prefix)

    if len(firmware_candidates) == 0:
        print("decryption failed!")
        print("(could not find a cipher that results in the part number being in the data)")
        exit(1)

    checksums = {
        "39990-TV9-A910": [
            (0x01f1e, 0x07fff),
            (0x08000, 0x225ff),
            (0x23200, 0x271ff),
            (0x27200, 0x295ff),
        ],
    }

    if len(firmware_candidates) > 1:
        print("multiple sets of keys resulted in data containing the part number")

    firmware_good = list()
    idx = 0
    for fc in firmware_candidates:
        # concat all address blocks to allow checksum validation using memory addresses
        # 连接所有地址块，以允许使用存储器地址进行校验和验证
        firmware = ''
        for block in xrange(len(fc)):
            start = fw.firmware_blocks[block]["start"]
            # fill gaps with \x00
            if len(firmware) < start:
                firmware += '\x00' * (start-len(firmware))
            firmware += fc[block]

        # validate known checksums  验证已知的校验和
        if f_base in checksums.keys():
            print("firmware[{}] checksums:".format(idx))
            match = True
            for start, end in checksums[f_base]:
                sum = ord(get_checksum(firmware[start:end]))
                chk = ord(firmware[end])
                print("{} {} {}".format(hex(chk), "=" if chk == sum else "!=", hex(sum)))
                if sum != chk:
                    match = False
            if match:
                print("checksums good!")
                firmware_good.append(firmware)
            else:
                print("checksums bad!")
        else:
            # no checksums so assume good
            firmware_good.append(firmware)
        
        idx += 1

    # sometimes more than one set of keys will result in the part number being found
    # hopefully the checksums narrowed it down to a single candidate
    # 有时，一组以上的密钥将导致找到零件号，希望校验和将其范围缩小到单个候选项
    if len(firmware_good) > 1:
        print("which firmware file is correct?  who knows!")

    idx = 1
    # write out decrypted firmware files
    for f_data in firmware_good:
        start_addr = fw.firmware_blocks[0]["start"]
        f_addr = hex(start_addr)
        f_out = os.path.join(f_dir, f_base + '.' + f_addr + '.bin')
        write_firmware(f_data[start_addr:], f_out)
        idx += 1

if __name__== "__main__":
    main()
