import sys

class varint:
        def __init__(self,handle):
            s=handle.read(1)
            if ord( s )>=253:
                s.join( handle.read(2<<(s&int('0x03',16)-1)) )
            self.s=s
        def __int__(self):
            if ord(self.s[0]) >=253:
                return int( ''.join('%02x'%ord( ch )for ch in self.s[1:] ) ,16)
            return ord(self.s[0])
        def __str__(self):
            return self.s
        def __repr__(self):
            return ''.join('%02x'%ord( ch )for ch in self.s)
            




class BlockFile:
    def __init__(self,filename):
        self.file=file(filename,'rb')
        self.txs=list()

    def getBlockFile(self):
        handle=self.file
        self.magic=''.join('%02x'%ord( ch )for ch in handle.read(4))
        self.blocksize=''.join('%02x'%ord( ch )for ch in handle.read(4))
        self.getBlock()
        #self.space=''.join('%02x'%ord( ch )for ch in handle.read(4))
        
    def getBlock(self):
        self.getBlockHeader()
        self.getBlockBody()

    def getBlockHeader(self):
        handle=self.file
        self.version=''.join('%02x'%ord( ch )for ch in handle.read(4))
        self.previousHash=''.join('%02x'%ord( ch )for ch in handle.read(32))
        self.merkleHash=''.join('%02x'%ord( ch )for ch in handle.read(32))
        self.timestamp=''.join('%02x'%ord( ch )for ch in handle.read(4))
        self.bits=''.join('%02x'%ord( ch )for ch in handle.read(4))
        self.nonce=''.join('%02x'%ord( ch )for ch in handle.read(4))

    def getBlockBody(self):
        self.getTxInfo()

    def getTxInfo(self):
        handle=self.file
        self.txcount=varint(handle)
        for i in range(int(self.txcount)):
            self.txs.append(dict())
            self.txs[i]['version']=''.join('%02x'%ord( ch )for ch in handle.read(4))
            self.txs[i]['numinput']=varint(handle)
            self.txs[i]['inputs']=list()
            for j in range(int(self.txs[i]['numinput'])):
                self.txs[i]['inputs'].append(self.getTxInput())
            self.txs[i]['numoutput']=varint(handle)
            self.txs[i]['outputs']=list()
            for j in range(int(self.txs[i]['numoutput'])):
                self.txs[i]['outputs'].append(self.getTxOutput())
            self.txs[i]['space']=''.join('%02x'%ord( ch )for ch in handle.read(4))

    def getTxInput(self):
        handle=self.file
        class TxInput:
            def __init__(self):
                self.previousOutputHash=''.join('%02x'%ord( ch )for ch in handle.read(32))
                self.previousOutputIndex=''.join('%02x'%ord( ch )for ch in handle.read(4))
                self.scriptLength=varint(handle)
                self.signatureScript=''.join('%02x'%ord( ch )for ch in handle.read(int(self.scriptLength)))
                self.sequence=''.join('%02x'%ord( ch )for ch in handle.read(4))
            def __str__(self):
                s=""
                s+=(self.previousOutputHash)
                s+=(self.previousOutputIndex)
                s+=( str(self.scriptLength ) )
                s+=(self.signatureScript)
                s+=(self.sequence)
                return s
            def __repr__(self):
                s=""
                s+="   tx input previousOutputHash:%s\n" % self.previousOutputHash
                s+="   tx input previousOutputIndex:%s\n" % self.previousOutputIndex
                s+="   tx input scriptLength:%s\n" % repr(self.scriptLength)
                s+="   tx input signatureScript:%s\n" % self.signatureScript
                s+="   tx input sequence:%s\n" % self.sequence
                return s
        return TxInput()

    def getTxOutput(self):
        handle=self.file
        class TxOutput:
            def __init__(self):
                self.value=''.join('%02x'%ord( ch )for ch in handle.read(8))
                self.pkScriptLength=varint(handle)
                self.pkScript=''.join('%02x'%ord( ch )for ch in handle.read(int(self.pkScriptLength)))
            def __str__(self):
                s=""
                s+=(self.value)
                s+=(str(self.pkScriptLength))
                s+=(self.pkScript)
                return s
            def __repr__(self):
                s=""
                s+="   tx output value:%s\n" % self.value
                s+="   tx output pkScriptLength:%s\n" % repr(self.pkScriptLength)
                s+="   tx output pkScript:%s\n" % self.pkScript
                return s
        return TxOutput()
    def __repr__(self):
        s=""
        s+="magic value:%s\n" % self.magic
        s+="blocksize:%s\n" % self.blocksize
        s+=" block version:%s\n" % self.version
        s+=" block previousHash:%s\n" %self.previousHash
        s+=" block merkleHash:%s\n" %self.merkleHash
        s+=" block timestamp:%s\n" %self.timestamp
        s+=" block bits:%s\n" %self.bits
        s+=" block nonce:%s\n" %self.nonce
        s+="  tx count:%s\n" %repr(self.txcount)
        for i in range(int(self.txcount)):
            s+="  tx version:%s\n" % self.txs[i]['version']
            s+="  tx numinput:%s\n" % repr(self.txs[i]['numinput'])
            for j in range(self.txs[i]['numinput']):
                s+=repr(self.txs[i]['inputs'][j])
            s+="  tx numoutput:%s\n" % repr(self.txs[i]['numoutput'])
            for j in range(self.txs[i]['numoutput']):
                s+=repr(self.txs[i]['outputs'][j])
            s+="  tx space:%s\n" % self.txs[i]['space']
        return s


if __name__=="__main__":
    
    block=BlockFile(sys.argv[1])
    for i in range(2732):
        block.getBlockFile()
    print repr(block)
    
    