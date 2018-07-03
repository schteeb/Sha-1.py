import timeit
#Define the left bit shift function
def rotateleft(n, b):
    return((n << b & ( 2 ** 32 - 1)) | (n >> 32 - b)) #Try different ROTATE

#Defining the helper functions as defined in the NIST.FIPS180
def ch(x, y, z):
    return ((x & y)^(~x & z))

def parity(x, y, z):
    return (x ^ y ^ z)

def maj(x, y, z):
    return ((x & y) ^ (x & z) ^ (y & z))


#Main SHA1 Function
def sha1(data):
    K =[]
    for i in range(80):
        if (i <= 19):
            K.append(0x5a827999)
        elif (i <= 39):
            K.append(0x6ed9eba1)
        elif (i <= 59):
            K.append(0x8f1bbcdc)
        else:
            K.append(0xca62c1d6)
#time for some padding
    padding = '1' + ('0' * (448 - (8 * len(str(data)) + 1))) + format(len(str(data)) * 8, '064b')
    databytes = bytearray(data, 'ascii')
    databits = [format(data, '08b') for data in databytes]
    datastr = ''.join(databits)
    datapadded = datastr + padding
    print("Padded data: " + datapadded)
    assert (len(datapadded) == 512)
    M = datapadded
    Hbuffers = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    N = len(datapadded) / 512
    for i in range(N, N + 1):
        Word = list()
        for t in range(80):
            if (t <= 15):
                Word.extend([int(M[(32 * t):(32 * (t + 1))], 2)])
            else:
                Word.extend([rotateleft(Word[t - 3] ^ Word[t - 8] ^ Word[t - 14] ^ Word[t - 16], 1)])
        print("Word Buffer:", Word[0:16])
        A = Hbuffers[0]
        B = Hbuffers[1]
        C = Hbuffers[2]
        D = Hbuffers[3]
        E = Hbuffers[4]
        for t in range(80):
            if (t<=19):
                f = ch
            elif(t<=39):
                f = parity
            elif(t<=59):
                f = maj
            else:
                f = parity
            Temp = (rotateleft(A, 5) + f(B, C, D) + E + K[t]+Word[t]) % (2 ** 32)
            E = D
            D = C
            C = (rotateleft(B, 30))
            B = A
            A = Temp
            print('Round ' + str(t), 'A:',hex(A), 'B:', hex(B), 'C:', hex(C), 'D:', hex(D), 'D:', hex(D))
        Hbuffers[0] = (A + Hbuffers[0]) % (2 ** 32)
        Hbuffers[1] = (B + Hbuffers[1]) % (2 ** 32)
        Hbuffers[2] = (C + Hbuffers[2]) % (2 ** 32)
        Hbuffers[3] = (D + Hbuffers[3]) % (2 ** 32)
        Hbuffers[4] = (E + Hbuffers[4]) % (2 ** 32)
    Hbuffers = [format(data, '08x') for data in Hbuffers]
    return(" ".join(Hbuffers)) #joins buffers together to produce final SHA1 digest

def main():
    print(sha1('abc'))

if __name__ == "__main__":
    main()