import sys

dll = open(sys.argv[1], 'rb').read()

res = ''
for i,ch in enumerate(dll):
    res += hex(ord(ch))+ ','
    if i % 15 == 0:
        res += '\n'

res = res.rstrip()
res = res.rstrip(',')
res = "unsigned int vncbuffer_len = "  + str(len(dll)) + ";\nunsigned char vncbuffer[] = \n{" + res + "};"

print(res)

