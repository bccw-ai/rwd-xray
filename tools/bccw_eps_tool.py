# place stock user.bin in /rwd-xray/tools and run 'python3 eps_tool.py'

import os
import sys
import subprocess
import struct
import hashlib
import binascii
import argparse

default_decrypt_lookup_table = {144: 72, 218: 55, 255: 255, 164: 1, 195: 26, 99: 2, 28: 178, 205: 158, 125: 138, 45: 118, 222: 98, 142: 78, 62: 58, 243: 38, 163: 18, 83: 254, 3: 234, 172: 214, 92: 194, 12: 174, 189: 154, 109: 134, 29: 114, 206: 94, 126: 74, 46: 54, 227: 34, 147: 14, 113: 0, 67: 250, 236: 230, 156: 210, 76: 190, 252: 170, 173: 150, 93: 130, 13: 110, 148: 253, 120: 159, 199: 148, 198: 137, 77: 126, 23: 104, 73: 83, 203: 73, 78: 62, 123: 53, 254: 42, 43: 33, 90: 23, 161: 12, 10: 3, 132: 249, 191: 239, 226: 220, 197: 201, 248: 191, 117: 181, 34: 172, 37: 161, 88: 151, 141: 142, 8: 131, 134: 121, 185: 111, 54: 101, 190: 90, 57: 79, 128: 68, 139: 57, 14: 46, 138: 35, 131: 10, 100: 241, 1: 228, 146: 200, 133: 185, 168: 171, 104: 155, 40: 139, 251: 85, 94: 66, 91: 45, 103: 124, 55: 112, 231: 156, 80: 56, 224: 92, 102: 113, 96: 60, 98: 188, 97: 252, 140: 206, 122: 31, 232: 187, 16: 40, 202: 51, 26: 7, 239: 251, 5: 153, 219: 77, 119: 128, 21: 157, 238: 102, 180: 5, 217: 119, 30: 50, 7: 100, 32: 44, 183: 144, 50: 176, 110: 70, 157: 146, 2: 164, 44: 182, 145: 8, 58: 15, 27: 29, 64: 52, 9: 67, 31: 199, 179: 22, 42: 11, 193: 20, 211: 30, 129: 4, 241: 32, 74: 19, 178: 208, 247: 160, 112: 64, 242: 224, 114: 192, 165: 193, 0: 36, 59: 37, 196: 9, 154: 39, 75: 41, 72: 147, 249: 127, 162: 204, 130: 196, 229: 209, 182: 133, 48: 48, 86: 109, 240: 96, 137: 99, 151: 136, 209: 24, 108: 198, 181: 197, 212: 13, 244: 21, 11: 25, 118: 117, 228: 17, 214: 141, 52: 229, 160: 76, 115: 6, 106: 27, 56: 143, 25: 71, 36: 225, 194: 212, 208: 88, 187: 69, 171: 65, 153: 103, 38: 97, 207: 243, 82: 184, 184: 175, 188: 218, 213: 205, 121: 95, 15: 195, 81: 248, 24: 135, 70: 105, 150: 125, 174: 86, 158: 82, 220: 226, 201: 115, 71: 116, 51: 246, 177: 16, 176: 80, 22: 93, 39: 108, 159: 231, 223: 247, 186: 47, 169: 107, 245: 213, 235: 81, 192: 84, 124: 202, 175: 235, 84: 237, 79: 211, 234: 59, 143: 227, 237: 166, 33: 236, 253: 106, 65: 244, 111: 219, 200: 179, 101: 177, 17: 232, 20: 221, 166: 129, 60: 186, 61: 122, 167: 140, 204: 222, 87: 120, 41: 75, 135: 132, 136: 163, 49: 240, 250: 63, 107: 49, 170: 43, 18: 168, 221: 162, 35: 242, 225: 28, 149: 189, 85: 173, 152: 167, 95: 215, 53: 165, 89: 87, 66: 180, 6: 89, 47: 203, 210: 216, 215: 152, 233: 123, 116: 245, 127: 223, 19: 238, 69: 169, 105: 91, 4: 217, 216: 183, 68: 233, 63: 207, 155: 61, 246: 149, 230: 145}

parser = argparse.ArgumentParser()
parser.add_argument("-stock", action="store_true")
args = parser.parse_args()

def param_to_data_string(param):
    # strip leading '0x'
    param = param.replace('0x','')
    param = param.replace(', ','')
    # pad to even number of characters (required by binascii)
    if len(param) % 2 == 1:
        param = '0' + param
    return binascii.a2b_hex(param)

def generate_file_header(indicator, headers):
    header_bytes = indicator
    for header in headers:
        header_bytes += chr(len(header))
        for item in header:
            header_bytes += chr(len(item.encode())) + str(item)
    return header_bytes

def checksum_by_sum(fw, start, end):
  s = 0
  for i in range(start, end - start, 2):
    s += struct.unpack('!H', fw[i:i + 2])[0]
  return s

# sum of -x, x is unsigned shorts
def checksum_by_negative_sum(fw, start, end):
  s = 0
  for i in range(start, end - start, 2):
    s += -struct.unpack('!H', fw[i:i + 2])[0]
  return s

checksum_funcs = [checksum_by_sum, checksum_by_negative_sum]

def main():
    hash_md5 = hashlib.md5()
    with open(os.path.join(sys.path[0], "user.bin"), "rb+") as f:
    #with open(os.path.join(sys.path[0], "39990TBX_3050M1__A2001900.0x13000.bin"), "rb+") as f:
        input_bin = f.read()
        fw_bytes = f

        print("user.bin len:", len(input_bin))
        if len(input_bin) == 393216:
            data_size = 0x4c000
            # 原始bin校验和的偏移量为0x4FF80和0x4FFFE，但是由于引导加载程序后从0x4000启动bin，因此我们相应地偏移了校验和
            checksum_offsets = [(0, 0x4bf80), (1, 0x4bffe)]
        elif len(input_bin) == 524288:
            data_size = 0x6c000
            checksum_offsets = [(0, 0x6bf80), (1, 0x6bffe)]

        input_bin_hash = hashlib.md5(input_bin).hexdigest()
        input_bin_hash == '79b695a73fd5ff22cbfeb4b83908ab29' 
        print('Detected bin: 39990-TLA-A040 Honda CR-V')
        supported_versions = ['39990-TLA-A030\x00\x00', '39990-TLA-A040\x00\x00', '39990-TLA,A040\x00\x00']
        security_key = ['\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20', '\x01\x11\x01\x12\x11\x20']
        version_offsets = [0xf8db, 0xf936, 0xf991, 0xf9ec, 0xfa47, 0xfaa2, 0xfafd, 0xfb58, 0xfbb3, 0xfc0e, 0xfc69, 0xfcc4]
        version_old = b'39990-TLA-A040'
        version_new = b'39990-TLA,A040'
        data_offsets = [
            0x11908, #speed_clamp_lo

            0x11b5e, #torque_table row 1 -> 18 byte
            0x11b70, #torque_table row 2
            0x11b82, #torque_table row 3
            0x11b94, #torque_table row 4
            0x11ba6, #torque_table row 5
            0x11bb8, #torque_table row 6
            0x11bca, #torque_table row 7

            0x11db0, #filter_table row 1 -> 63

            0x11eac, #new_table row 1 -> 63

            0x119ae, #speed_table row 1 -> 63
            ]
        data_old = [
            '0x0028', #speed_clamp_lo

            '0x0000, 0x0500, 0x0a15, 0x0e6d, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 1
            '0x0000, 0x0500, 0x0a15, 0x0e6d, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 2
            '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 3
            '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 4
            '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 5
            '0x0000, 0x06b3, 0x0bf8, 0x0ebb, 0x1078, 0x1200, 0x1317, 0x1400, 0x1400', # original torque_table row 6
            '0x0000, 0x06e1, 0x0c9a, 0x1000, 0x1100, 0x1200, 0x129a, 0x134d, 0x1400', # original torque_table row 7

            '0x009f, 0x0100, 0x0180, 0x01e6, 0x01e6, 0x01e6, 0x01e6, 0x01e6, 0x01e6', #filter_table row 1

            '0x0021, 0x004d, 0x0096, 0x00c0, 0x00cb, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 1

            '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 1
            ]
        data_new = [
            '0x0000', #speed_clamp_lo

            '0x0000, 0x0500, 0x0A15, 0x0E6D, 0x1100, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 1
            '0x0000, 0x0500, 0x0A15, 0x0E6D, 0x1100, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 2
            '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 3
            '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 4
            '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 5
            '0x0000, 0x06B3, 0x0BF8, 0x0EBB, 0x1078, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 6
            '0x0000, 0x06E1, 0x0C9A, 0x1000, 0x1100, 0x1200, 0x1955, 0x20AA, 0x2800', # new torque_table row 7

            '0x009f, 0x0100, 0x0180, 0x01e6, 0x01e6, 0x01e6, 0x0200, 0x0200, 0x0200', # filter_table row 1

            '0x0021, 0x004d, 0x0096, 0x00c0, 0x00cb, 0x00cd, 0x00cd, 0x00cd, 0x00cd', #new_table row 1

            '0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee, 0x06ee', #speed_table row 1
            ]
        data_label = [
            'speed_clamp_lo',

            'torque_table row 1',
            'torque_table row 2',
            'torque_table row 3',
            'torque_table row 4',
            'torque_table row 5',
            'torque_table row 6',
            'torque_table row 7',

            'filter_table row 1',

            'new_table row 1',

            'speed_table row 1'
            ]


## do patch
    if args.stock:
        print('Patch bypassed, making stock RWD')
        with open(os.path.join(sys.path[0], "user.bin"), 'rb+') as f:
            full_fw = f.read()
            patch_fw = full_fw[0x4000:(0x4000 + data_size)]
    else:
        with open(os.path.join(sys.path[0], "user_patched.bin"), 'wb+') as output_bin:
            output_bin.write(input_bin)
            for version_offset in version_offsets:
                output_bin.seek(version_offset)
                # validate original version  验证原始版本
                version_old_actual = output_bin.read(int(len(version_old)))
                #assert version_old_actual == version_old, 'Check fw version at offset {}: expected {} but found {}'.format(hex(version_offset), version_old, version_old_actual.decode())
                #validate new version length
                assert len(version_old) == len(version_new), 'New fw version length error. {} is {} bytes, {} is {} bytes.'.format(version_old, len(version_old), version_new, len(version_new))
                output_bin.seek(version_offset)
                output_bin.write(version_new)
            print("Update fw version at offsets {}:".format(', '.join(hex(x) for x in version_offsets)))
            print("  Old Data: {}".format(version_old.decode()))
            print("  New Data: {}".format(version_new.decode()))
            #assert len(data_offsets) == len(data_old) == len(data_new) == len(data_label), 'Number of data items mismatch!'
            for data_offsets, data_old, data_new, data_label in zip(data_offsets, data_old, data_new, data_label):
                if data_new != data_old:
                    data_old_bytes = param_to_data_string(data_old)
                    data_new_bytes = param_to_data_string(data_new)
                    output_bin.seek(data_offsets)
                    #validate original data
                    data_old_actual = output_bin.read(int(len(data_old_bytes.hex())/2))
                    #assert data_old_actual == data_old_bytes, 'Check {} at offset {}: expected {} but found {}'.format(data_label, hex(data_offsets), str(data_old_bytes), str(data_old_actual))
                    #validate original data length
                    #assert len(data_old) == len(data_new), '{} data length error. {} is {} bytes, {} is {} bytes'.format(data_label, data_old, len(data_old_bytes), data_new, len(data_new_bytes))
                    output_bin.seek(data_offsets)
                    output_bin.write(data_new_bytes)
                    print("Update {} at offset {}:".format(data_label, hex(data_offsets)))
                    print("  Old Data: {}".format(str(data_old)))
                    print("  New Data: {}".format(str(data_new)))
            output_bin.seek(0x4000)
            patch_fw = output_bin.read(data_size)
            for func_idx, off in checksum_offsets:
                old_checksum = struct.unpack('!H', patch_fw[off:off+2])[0]
                new_checksum = checksum_funcs[func_idx](patch_fw, 0, off) & 0xFFFF
                if new_checksum != old_checksum:
                    print('Update checksum at offset {} from {} to {}'.format(hex(off),  hex(old_checksum), hex(new_checksum)))
                    patch_fw = patch_fw[:off] + struct.pack('!H', new_checksum & 0xFFFF) + patch_fw[off+2:]
            output_bin.seek(0x4000)
            output_bin.write(patch_fw)
            #validate patched fw length
            output_bin.seek(0)
            new_fw = output_bin.read()
            output_bin_hash = hashlib.md5(new_fw).hexdigest()
            with open(os.path.join(sys.path[0], "user.bin"), 'rb') as input_bin:
                old_fw = input_bin.read()
                #assert len(new_fw) == len(old_fw), 'New fw length error. Old:{}, New:{}'.format(len(old_fw), len(new_fw))
        print('Patch done, hash = {}. Saved to rwd-xray/tools/user_patched.bin Encrypting...'.format(output_bin_hash))


## do encryption
    encrypt_lookup_table = {}
    for k, v in default_decrypt_lookup_table.items():
        encrypt_lookup_table[v] = k
    encrypted = bytearray()
    for b in patch_fw:
        encrypted.append(encrypt_lookup_table[b])
    with open(os.path.join(sys.path[0], "user_patched.enc"), 'wb') as encrypted_bin_out:
        encrypted_bin_out.write(encrypted)
        encrypted_bin_hash = hashlib.md5(encrypted).hexdigest()
        print('Encryption done, hash = {}. Saved to rwd-xray/tools/user_patched.enc Building RWD...'.format(encrypted_bin_hash))


## build rwd
    start_addr = param_to_data_string(hex(0x4000))
    data_siz = param_to_data_string(hex(data_size))

    indicator = '\x5A\x0D\x0A' # CAN format
    headers = [
        ['\x00'], # always zero
        [], # always empty
        ['\x30'], # significant byte in 29 bit addr (0x18da__f1)
        supported_versions, # previous firmware version(s)
        security_key, # security access key (one per prev firmware version)
        ['\x01\x02\x03'], # firmware encryption key
    ]

    for i in range(len(headers)):
        print('[Header {}]: {}'.format(i, headers[i]))

    rwd_header_bytes = generate_file_header(indicator, headers)

    rwd_start_len = start_addr.rjust(4, b'\x00') + data_siz.rjust(4, b'\x00')
    file_checksum = sum(rwd_header_bytes.encode()+rwd_start_len+encrypted) & 0xFFFFFFFF

    print('File checksum: {}'.format(hex(file_checksum)))
    rwd_checksum_bytes = struct.pack('<L', file_checksum)

    if args.stock:
        out_rwd_path = os.path.join(sys.path[0], "user.rwd")
    else:
        out_rwd_path = os.path.join(sys.path[0], "user_patched.rwd")
    with open(out_rwd_path, 'wb+') as f:
        f.write(rwd_header_bytes.encode())
        f.write(rwd_start_len)
        f.write(encrypted)
        f.write(rwd_checksum_bytes)
        rwd_hash = hashlib.md5(rwd_header_bytes.encode()+rwd_start_len+encrypted+rwd_checksum_bytes).hexdigest()
        print('RWD built, hash = {}. saved to rwd-xray/tools/user_patched.rwd'.format(rwd_hash))
    print("Done!")


main()
