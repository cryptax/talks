# A. Apvrille - De-obfuscation of Android/MysteryBot strings

def demo(thestring, x1=53, x2=66):
    decoded = ''
    index = len(thestring) -1
    while (index >=0):
        decoded = chr(ord(thestring[index]) ^ x1) + decoded
        if (index - 1) < 0:
            break
        index = index - 1
        decoded = (chr(ord(thestring[index]) ^ x2)) + decoded
        index = index - 1
    return decoded

s = 'T,Q0Z+QlT2ElT!A+Z,\u001B\u0003q\u0006j\u0006p\u0014|\u0001p\u001Dt\u0006x\u000B{'
print demo(s.decode('unicode-escape'))

s = "*~/b$y/>*`;>.h?b*>\u000FU\u001DY\bU\u0014Q\u000F]\u0002^"
print demo(s.decode('unicode-escape'), 16,75)

s = 'T,Q0Z+QlT2ElP:A0Tlt\u0006q\u001Dp\u001Ae\u000Et\ft\u0016|\r{'
print demo(s.decode('unicode-escape'))

s = 'D$0>`/q?ukd#ukf.b8y$~'
print demo(s.decode('unicode-escape'), 16,75)

s = '$Z0V\'\u0018.Z!^\'Q'
print demo(s.decode('unicode-escape'))
