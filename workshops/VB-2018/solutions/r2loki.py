#! /usr/bin/env python
#
# A. Apvrille - August 23, 2018
#
# radare2 script to decode Android/LokiBot obfuscated strings
#
# Requirement: r2pipe (e.g. pip install r2pipe)
# Run from r2: #!pipe python r2loki.py str.symbol
# e.g. #!pipe python ../r2loki.py str.b6g_l1gvj6w_m__9__j7mv__O_

import r2pipe
import sys

def usage():
    print 'Usage: python r2loki.py stringaddr'
    print 'stringaddr: the address of the obfuscated string. The first byte should be the length of the string'

# -----------------------------------------
# quick argument check
if len(sys.argv) != 2:
    usage()
    quit()

def deobfuscate(s, key1=88, key2=3):
    result = list(s)
    # s is an obfuscated string
    i = len(s) -1
    while i >= 0:
        result[i] = chr(ord(result[i]) ^ key1)
        i = i -1
        if i >= 0:
            result[i] = chr(ord(result[i]) ^ key2)
        i = i -1
    return ''.join(result)

# go to address and retrieve bytes    
r2p=r2pipe.open()
obfuscated_string_address = sys.argv[1]

# following will only work if 1st byte contains the length of the string
obfuscated_string_len = int(r2p.cmd('s '+ sys.argv[1] + ' ; p8 1'), 16)
print 'Estimated length: ',obfuscated_string_len

# get string bytes
obfuscated_string = r2p.cmd('s '+sys.argv[1]+'+1 ; p8 %d' % (obfuscated_string_len))
print 'Obfuscated hex bytes: ',obfuscated_string

# de-obfuscate with the adequate constants
print 'De-obfuscated Result: ', deobfuscate(obfuscated_string.decode('hex'), 88,3)

