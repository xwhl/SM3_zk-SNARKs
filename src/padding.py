import sys
from gmssl import sm3

def sm3_hash(msg):
    # print(msg)
    len1 = len(msg)
    for i in range(len1):
        msg[i] = ord(msg[i])
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])
    return msg

print('预填充处理，填充消息为:',sys.argv[1])
print('填充结果为:')
pad = sm3_hash(list(sys.argv[1]))
res = ''
for i in range(16):
    subres=''
    for j in range(4):
        subres = '%s%02x' % (subres, pad[4*i+j])
    subres = '0x%s' % subres
    res = '%s%s ' % (res,subres)
print(res)

print('对应sm3计算值为:')
input = list(sys.argv[1])
len1 = len(input)
for i in range(len1):
    input[i] = ord(input[i])
ha = sm3.sm3_hash(input)
fha = ''
for i in range(8):
    subha = '0x%s' % ha[i*8:i*8+8]
    fha = '%s%s ' % (fha,subha)
print(fha)



