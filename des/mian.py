from des import operation as op


def encry(plaintext, key):
    '''主加密函数（轮函数）'''
    plaintext = op.string2bin(plaintext)
    text = op.IpPermutation(plaintext)
    k0 = op.string2bin(key)
    kn = op.createSubKey(k0)
    for i in range(16):
        l, r = text[:32], text[32:]
        resE = op.ExtendPermutation(r)
        resXor1 = op.xor(resE, kn[i])
        resS = op.SBoxPermutation(resXor1)
        resP = op.PBoxPermutation(resS)
        resXor2 = op.xor(resP, l)
        text = r + resXor2
    text = text[32:] + text[0:32]
    return op.bin2string(op.InverseIpPermutation(text))


def decry(ciphertext, key):
    '''主解密函数（轮函数）'''
    ciphertext = op.string2bin(ciphertext)
    text = op.IpPermutation(ciphertext)
    k0 = op.string2bin(key)
    kn = op.createSubKey(k0)
    for i in range(16):
        l, r = text[:32], text[32:]
        resE = op.ExtendPermutation(r)
        resXor1 = op.xor(resE, kn[15 - i])
        resS = op.SBoxPermutation(resXor1)
        resP = op.PBoxPermutation(resS)
        resXor2 = op.xor(resP, l)
        text = r + resXor2
    text = text[32:] + text[0:32]
    return op.bin2string(op.InverseIpPermutation(text))


if __name__ == '__main__':
    while 1:
        print("--DES加解密--")
        print("--1.DES加密--")
        print("--2.DES解密--")
        print("---0.退出----")
        n=input("输入数字操作")
        if n=='1':
            print("你正在使用DES加密")
            plain = input("输入明文 长度不为8的倍数将自动填充'Q'")
            key = input("输入密钥 长度不为8的倍数将自动填充'S'")
            plain += (8 - len(plain) % 8) * 'Q'
            key += (8 - len(key) % 8) * 'S'
            c = ""
            for i in range(int(len(plain) / 8)):
                c = c + encry(plain[i * 8:(i + 1) * 8], key)
            print("加密完成|密文:", "\033[1;32;40m",c,"\033[0m")
        elif n=='2':
            print("你正在使用DES解密")
            c = input("输入密文")
            key = input("输入密钥 长度不为8的倍数将自动填充'S'")
            key += (8 - len(key) % 8) * 'S'
            m = ""
            for i in range(int(len(c) / 8)):
                m += decry(c[i * 8:(i + 1) * 8], key)
            print("解密完成|明文:", "\033[1;32;40m",m,"\033[0m")
        elif n=='0':
            break;
        else:
            print("重新输入")
