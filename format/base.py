# -*- coding: utf-8 -*-
import sys
import struct
import operator
import itertools
import re             # 正则表达式是独立于任何语言的一种字符串匹配表达式，

class Base(object):
    def __init__(self, data, headers, keys, addr_blocks, encrypted):
        self._file_format = data[0:1]
        self._file_headers = headers
        self._file_checksum = struct.unpack('<L', data[-4:])[0]
        self._firmware_blocks = addr_blocks
        self._firmware_encrypted = encrypted
        self._keys = keys

        self.validate_file_checksum(data)

    @property
    def file_format(self):
        return self._file_format

    @property
    def file_checksum(self):
        return self._file_checksum

    @property
    def file_headers(self):
        return self._file_headers

    @property
    def firmware_blocks(self):
        return self._firmware_blocks

    @property
    def firmware_encrypted(self):
        return self._firmware_encrypted

    @property
    def keys(self):
        return self._keys

    def calc_checksum(self, data):
        result = -sum(map(ord, data))
        return chr(result & 0xFF)

    def validate_file_checksum(self, data):
        calculated = sum(map(ord, data[0:-4])) & 0xFFFFFFFF
        assert calculated == self.file_checksum, "file checksum mismatch"

    def _get_decoder(self, key1, key2, key3, op1, op2, op3):
        decoder = {}
        # set() 函数创建一个无序不重复元素集，可进行关系测试，删除重复数据，还可以计算交集、差集、并集等；iterable -- 可迭代对象对象；
        values = set()

        for e in range(256):
            # cipher: (((i ^ k0) ^ k1) - k2) & 0xFF  将 0 加密计算为 49
            d = op3(op2(op1(e, key1), key2), key3) & 0xFF
            decoder[chr(e)] = chr(d)                       # 将 d = Unicode码 转换为 整数 chr(d) 
            values.add(d)                                  # set.add() 方法用于给集合添加元素，如果添加的元素在集合中已存在，则不执行任何操作。

        return decoder if len(values) == 256 else None

    def decrypt(self, search_value):
        search_value_padded = ''.join(map(lambda c: c + '.', search_value))
        print("decrypt-search:")
        print("search_value = {}".format(search_value))
        print("search_value_paddad = {}".format(search_value_padded))

        # search_exact = .*39990-TVE-3050.*
        search_exact = re.compile('.*'+search_value+'.*', flags=re.IGNORECASE|re.MULTILINE|re.DOTALL)  # 精确搜索
        print("search_exact = {}".format(search_exact.pattern))
        # 正则表达式是独立于任何语言的一种字符串匹配表达式 https://blog.csdn.net/liuweiyuxiang/article/details/102484297
        # “.”：匹配除了换行符以外的任何字符。这个算是"\w"的加强版了"\w"不能匹配 空格 如果把字符串加上空格用"\w"就受限了
        # “*”(贪婪) 重复零次或更多。例如"aaaaaaaa" 匹配字符串中所有的a 正则： “a*” 会出到所有的字符"a"
        # 看下用 “.“是如何匹配字符"a23 4 5 B C D__TTz” 正则：”.+"
        # sometimes there is an extra character after each character
        # 有时每个字符后面都有一个额外的字符
        # 37805-RBB-J530 -> 3377880550--RRBCBA--JA503000
        # search_padded = .*3.9.9.9.0.-.T.V.E.-.3.0.5.0..*; 
        # re.IGNORECASE: 进行忽略大小写匹配；re.MULTILINE: ’^’ 匹配字符串头，'$' 匹配字符串尾。
        # re.DOTALL: 让 '.' 特殊字符匹配任何字符，包括换行符
        search_padded = re.compile('.*'+search_value_padded+'.*', flags=re.IGNORECASE|re.MULTILINE|re.DOTALL)  # 填充搜索
        print("search_padded = {}".format(search_padded.pattern))
        operators = [
            { 'fn': operator.__xor__, 'sym': '^' },  # operator.__xor__(a, b) 返回 a 和 b 按位异或的结果。
            { 'fn': operator.__and__, 'sym': '&' },  # operator.__and__(a, b) 返回 x 和 y 按位与的结果。
            { 'fn': operator.__or__,  'sym': '|' },  # operator.__or__(a, b) 返回 a 和 b 按位或的结果。
            { 'fn': operator.__add__, 'sym': '+' },  # 对于数字 a 和 b，返回 a + b。
            { 'fn': operator.__sub__, 'sym': '-' },
            { 'fn': operator.__mul__, 'sym': '*' },
            { 'fn': operator.__div__, 'sym': '/' },
            { 'fn': operator.__mod__, 'sym': '%' },
        ]

        keys = list()
        print("self._keys = {}".format(self._keys), self._keys)
        for i in range(len(self._keys)):
            k = ord(self._keys[i])  # ord(字符): 返回值是对应的十进制整数; chr(数字): 返回值是当前整数对应的 ASCII 字符。
            #print("k = {}".format(k))
            keys.append({ 'val': k, 'sym': 'k{}'.format(i) })
            #print("keys = {}".format(keys))
        assert len(keys) == 3, "excatly three keys currently required!"

        firmware_candidates = list()

        # 排列组合迭代器：长度r元组，所有可能的排列，无重复元素: permutations('ABCD', 2) => AB AC AD BA BC BD CA CB CD DA DB DC
        # keys = [{'sym': 'k0', 'val': 191}, {'sym': 'k1', 'val': 16}, {'sym': 'k2', 'val': 158}]
        # key_perms = 
        #    [ ({'sym': 'k0', 'val': 191}, {'sym': 'k1', 'val': 16},  {'sym': 'k2', 'val': 158}), 
        #      ({'sym': 'k0', 'val': 191}, {'sym': 'k2', 'val': 158}, {'sym': 'k1', 'val': 16}), 
        #      ({'sym': 'k1', 'val': 16},  {'sym': 'k0', 'val': 191}, {'sym': 'k2', 'val': 158}), 
        #      ({'sym': 'k1', 'val': 16},  {'sym': 'k2', 'val': 158}, {'sym': 'k0', 'val': 191}), 
        #      ({'sym': 'k2', 'val': 158}, {'sym': 'k0', 'val': 191}, {'sym': 'k1', 'val': 16}), 
        #      ({'sym': 'k2', 'val': 158}, {'sym': 'k1', 'val': 16},  {'sym': 'k0', 'val': 191}) ]
        key_perms = list(itertools.permutations(keys))
        #print("key_perms = ", key_perms)
        # 排列组合迭代器：笛卡尔积，相当于嵌套的for循环，product('ABCD', repeat=2) AA AB AC AD BA BB BC BD CA CB CC CD DA DB DC DD
        # { [...
        #   ({'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '|', 'fn': <built-in function __or__>}), 
        #
        #   ({'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '+', 'fn': <built-in function __add__>}), 
        #
        #   ({'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '-', 'fn': <built-in function __sub__>}), 
        #   
        #   ({'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '*', 'fn': <built-in function __mul__>}), 
        #   
        #   ({'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '/', 'fn': <built-in function __div__>}), 
        #
        #   ({'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}, 
        #    {'sym': '%', 'fn': <built-in function __mod__>}) ]
        op_perms = list(itertools.product(operators, repeat=3))
        #print("op_perms = {}".format(op_perms))
        display_ciphers = list()      # 显示密码
        attempted_decoders = list()   # 尝试的解码器
        for k1, k2, k3 in key_perms:
            for o1, o2, o3 in op_perms:
                decoder = self._get_decoder(
                    k1['val'], k2['val'], k3['val'],
                    o1['fn'], o2['fn'], o3['fn'])
                #print("decoder = {}".format(decoder))
                
                if decoder is None or decoder in attempted_decoders:
                    continue
                attempted_decoders.append(decoder)
                #print("attemted_decoders = {}".format(attempted_decoders))

                candidate = [map(lambda x: decoder[x], e) for e in self._firmware_encrypted]
                #print("candidate = {}".format(candidate))
                decrypted = ''.join([c for l in candidate for c in l])
                #print("decrypted = ", decrypted)
                #print("search_exact.match = {}".format(search_exact.match(decrypted)))
                #print("search_padded.match = {}".format(search_padded))
                #print("==========================")
                if (search_exact.match(decrypted) or search_padded.match(decrypted)) and candidate not in firmware_candidates:
                    sys.stdout.write('X')
                    firmware_candidates.append([''.join(c) for c in candidate])
                    display_ciphers.append(
                        "(((i {} {}) {} {}) {} {}) & 0xFF".format(
                            o1['sym'], k1['sym'],
                            o2['sym'], k2['sym'],
                            o3['sym'], k3['sym']))
                else:
                    sys.stdout.write('.')
                sys.stdout.flush()  #  缓冲区的刷新方式：flush()刷新缓存区 | 缓冲区满时，自动刷新 | 文件关闭或者是程序结束自动刷新

        print("")
        for cipher in display_ciphers:
            print("cipher: {}".format(cipher))
        #print("firmware_candidates = {}".format(firmware_candidates))
        return firmware_candidates


    def __str__(self):
        info = [
            "file format: {}".format(self.file_format),
            "file checksum: {}".format(hex(self.file_checksum)),
        ]
        info.append("headers:")
        info.extend([str(h) for h in self._file_headers])
        info.append("keys:")
        info.extend([
            "k{} = {}".format(i, hex(ord(self._keys[i])))
            for i in range(len(self._keys))
        ])
        info.append("address blocks:")
        info.extend([
            "start = {} len = {}".format(hex(i["start"]), hex(i["length"]))
            for i in self._firmware_blocks
        ])

        return '\n'.join(info)
