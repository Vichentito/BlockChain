from cryptography.hazmat.primitives import hashes


class someClass:
    string = None
    num = 23145
    def __init__(self, mystring):
        self.string = mystring

    def __repr__(self):
        return self.string +"^^^"+str(self.num)


class CBlock:
    data = None
    previousHash = None
    previousBlock = None

    def __init__(self, data, previousBlock):
        self.data = data
        self.previousBlock = previousBlock
        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()

    def computeHash(self):
        digest = hashes.Hash(hashes.SHA384())
        digest.update(bytes(str(self.data), 'utf-8'))
        digest.update(bytes(str(self.previousHash), 'utf-8'))
        return digest.finalize()
    
    def is_valid(self):
        if self.previousBlock == None :
            return True
        return self.previousBlock.computeHash() == self.previousHash

if __name__ == '__main__':
    root = CBlock('I am root', None)
    B1 = CBlock('I am i child', root)
    B2 = CBlock('I am b1 brother', root)
    B3 = CBlock(1234, B1)
    B4 = CBlock(someClass('Hi there!'), B3)
    B5 = CBlock("Top Block", B4)
    for b in [B1, B2, B3, B4, B5]:
        if B1.previousBlock.computeHash() == B1.previousHash:
            print("Success! Hash is good")
        else:
            print("Error! Hash is not good")

    B3.data = 1243
    if B4.previousBlock.computeHash() == B4.previousHash:
        print("Error! Couldn't detect tampering")
    else:
        print("Success! Tampering detected")
    B4.data.num = 00000
    if B5.previousBlock.computeHash() == B5.previousHash:
        print("Error! Couldn't detect tampering")
    else:
        print("Success! Tampering detected")
