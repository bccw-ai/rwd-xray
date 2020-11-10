# -*- coding: utf-8 -*-
import struct
from base import Base
from header import Header
from header_value import HeaderValue

class x5a(Base):
    def __init__(self, data):
        start_idx                = 3                                           # skip file type indicator bytes  跳过文件类型指示符字节
        headers, header_data_len = self._parse_file_headers(data[start_idx:])
        keys                     = self._get_keys(headers)
        
        start_idx               += header_data_len
        addr_blocks, encrypted   = self._get_firmware(data[start_idx:-4])      # exclude file checksum  排除文件校验和
        
        # @初始化父类
        Base.__init__(self, data, headers, keys, addr_blocks, encrypted)

    def _parse_file_headers(self, data):
        headers = list()
        d_idx = 0

        for h_idx in range(6):
            h_prefix = data[d_idx]
            d_idx += 1

            # first byte is number of values
            cnt = ord(h_prefix)

            f_header = Header(h_idx, h_prefix, "")
            for v_idx in range(cnt):
                v_prefix = data[d_idx]
                d_idx += 1

                # first byte is length of value
                length = ord(v_prefix)
                v_data = data[d_idx:d_idx+length]
                d_idx += length

                h_value = HeaderValue(v_prefix, "", v_data)
                f_header.values.append(h_value)

            headers.append(f_header)

        return headers, d_idx

    def _get_keys(self, headers):
        for header in headers:
            if header.id == 5:
                assert len(header.values) == 1, "encryption key header does not have exactly one value!"
                assert len(header.values[0].value) == 3, "encryption key header not three bytes!"
                return header.values[0].value

        raise Exception("could not find encryption key header!")

    def _get_firmware(self, data):
        # python 中的struct主要是用来处理C结构数据的，读入时先转换为Python的 字符串 类型，
        # 然后再转换为Python的结构化类型，一般输入的渠道来源于文件或者网络的二进制流。
        # 在转化过程中，主要用到了一个格式化字符串(format strings)，用来规定转化的方法和格式。
        start  = struct.unpack('!I', data[0:4])[0]
        length = struct.unpack('!I', data[4:8])[0]

        firmware = data[8:]
        assert len(firmware) == length, "firmware length incorrect!"
        return [{"start": start, "length": length}], [firmware]












