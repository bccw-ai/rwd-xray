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
    print("f_dir = {}".format(f_dir), f_dir)
    # 3999-TAX-XXX.bin => split('.')[0]表示把指定的字符串按照"."来拆分成字符串数组.结果是：{a,b,c,d}
    f_base   = os.path.basename(f_name).split('.')[0]  # basename()返回path最后的文件名
    print("f_base = {}".format(f_base))
    f_raw    = read_file(f_name)                       # 获取固件的原始数据
    #print("f_raw = {}".format(f_raw)) 
    f_type   = "x" + binascii.b2a_hex(f_raw[0])        # 把 固件 转换成二进制数据然后再用十六进制表示
    print("f_type = {}".format(f_type)) 
    # 一个函数运行需要根据不同项目的配置，动态导入对应的配置文件运行。importlib允许程序员创建他们自定义的对象，可用于引入过程（也称为importer）。
    # importlib.import_module('b.c.c') # 绝对导入
    # importlib.import_module('.c.c',package='b') # 相对导入
    # f_module = <module 'format.x5a' from '/Users/bccw/bccw-ai/rwd-xray/format/x5a.pyc'>
    f_module = importlib.import_module("format.{}".format(f_type))
    print("f_module = {}".format(f_module))  
    # getattr(对象，对象属性) 函数用于返回一个对象属性值。
    f_class  = getattr(f_module, f_type)
    print("f_class = {}".format(f_class)) 
    fw       = f_class(f_raw)
    print("bfw = {}".format(fw))

    fenc_name = os.path.join(f_dir, f_base + '.enc')
    print("fenc_name = {}".format(fenc_name))
    #with open(fenc_name, 'wb+') as fenc:
    #  for fe in fw.firmware_encrypted:
    #    print("fe = {}".format, fe)
    #    break

if __name__ == "__main__":
    main()

