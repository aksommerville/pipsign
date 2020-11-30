#!/usr/bin/env python

import sys
import md5

# Must match what's in PippinAuthenticationFile.
COPYRIGHT="Copyright Apple Computer, Inc.    1995. All rights reserved.\0\0\0\0"

if len(sys.argv)!=2:
  raise Exception("Usage: %s DISKIMAGE"%(sys.argv[0],))
  
imagepath=sys.argv[1]
src=open(imagepath,"rb").read()

print "%s: Length %d"%(imagepath,len(src))

def rd32(p):
  return (ord(src[p])<<24)|(ord(src[p+1])<<16)|(ord(src[p+2])<<8)|ord(src[p+3])

def rdpaf32(p):
  p+=pafp
  return (ord(srcwithpaf[p])<<24)|(ord(srcwithpaf[p+1])<<16)|(ord(srcwithpaf[p+2])<<8)|ord(srcwithpaf[p+3])
  
def hexbytes(src):
  return ''.join(map(lambda ch:"%02x"%(ord(ch),),src))

#------------------ Locate PippinAuthenticationFile -----------------------

pafblock=rd32(0x5f8)
pafsize=rd32(0x5fc)
pafp=pafblock*512
if pafp<=0 or pafsize<80+64 or pafp>len(src)-pafsize:
  raise Exception("MDB indicates PAF at block 0x%08x, length 0x%08x bytes -- impossible!"%(pafblock,pafsize))
    
print "Located PAF at 0x%08x, length %d"%(pafp,pafsize)

# Zero out the PAF.
srcwithpaf=src
src=src[:pafp]+"\0"*(pafsize)+src[pafp+pafsize:]

#--------------------- Hash each chunk --------------------------------

def cleanse_mdb(src):
  def restore(dst,src,p,c):
    return dst[:p]+src[p:p+c]+dst[p+c:]
  tmp=src[:0x600]
  src=src[:0x3f8]+"\0"*178+src[0x3f8+178:]
  src=restore(src,tmp,0x402,4)
  src=restore(src,tmp,0x40c,2)
  src=restore(src,tmp,0x40e,2)
  src=restore(src,tmp,0x412,2)
  src=restore(src,tmp,0x41e,4)
  src=restore(src,tmp,0x422,2)
  src=restore(src,tmp,0x424,28)
  return src

chunk_size_expected=128*1024
sigoffset=rdpaf32(0)
chunk_size=rdpaf32(72)
if chunk_size!=chunk_size_expected:
  raise Exception("Chunk size should be %d, but PippinAuthenticationFile says %d"%(chunk_size_expected,chunk_size))
physical_chunkc=len(src)/chunk_size
logical_chunkc=rdpaf32(76)
if physical_chunkc!=logical_chunkc:
  print "!!! %s: Image has %d chunks but PippinAuthenticationFile says %d. We'll use the lower."%(imagepath,physical_chunkc,logical_chunkc)
chunkc=min(physical_chunkc,logical_chunkc)
print "%s: %d chunks of size %d"%(imagepath,chunkc,chunk_size)

for chunkp in xrange(chunkc):
  physical_offset=chunkp*chunk_size
  if chunkp==0:
    chunkhash=md5.md5(cleanse_mdb(src[physical_offset:physical_offset+chunk_size])).digest()
  else:
    chunkhash=md5.md5(src[physical_offset:physical_offset+chunk_size]).digest()
  tocp=pafp+80+16*chunkp
  statedhash=srcwithpaf[tocp:tocp+16]
  if chunkhash!=statedhash:
    print "!!! %s: chunk %d/%d hash mismatch"%(imagepath,chunkp,chunkc)
    print "   In PAF: %s"%(hexbytes(statedhash),)
    print "  On disk: %s"%(hexbytes(chunkhash),)
  else:
    pass#print"%s: chunk %d/%d ok: %s"%(imagepath,chunkp,chunkc,hexbytes(statedhash))
    
pafchunk=pafp/chunk_size
#print "If you got a mismatch around chunk %d, that is where PippinAuthenticationFile itself is located."%(pafchunk,)
  
#------------------------ Assemble PippinAuthenticationFile Message part and hash it -------------

message=srcwithpaf[pafp:pafp+sigoffset]
messagehash=md5.md5(message).digest()

print "%s: Hash of PippinAuthenticationFile's TOC: %s"%(imagepath,hexbytes(messagehash))

#---------------- Read the signature and decode it with Apple's public key --------------------

#sigp=pafp+80+16*logical_chunkc+19
encsig=srcwithpaf[pafp+sigoffset+4:pafp+sigoffset+49]

print "%s: Encrypted signature: %s"%(imagepath,hexbytes(encsig))

d=0x011CD3ADE7998667D6E9E21711DBEC3307B60E4D6D032620775DDB9B3B64CF22B20E4AF32F0740EEB06F85F2A01D
e=0x10001
p=0x0F2D25BF3C5B7028726E49753FD562671137389451EFD7
q=0x0ED1475DE1924128592C4B3E474E5FC1231F1BAFA0D82B
n=p*q

# Encrypted signature as a long
encsign=0
for ch in encsig:
  encsign<<=8
  encsign|=ord(ch)

# Copied from reference code by Kevin Almansa
def right_to_left(b,exp,mod):
  ret=1
  b=b%mod
  while exp>0:
    if exp&1:
      ret=(ret*b)%mod
    exp=exp>>1
    b=(b*b)%mod
  return ret
plainsign=right_to_left(encsign,e,n)

# Plaintext signature as a string
plainsig=""
while plainsign>0:
  plainsig=chr(plainsign&0xff)+plainsig
  plainsign>>=8
while len(plainsig)<len(encsig):
  plainsig="\0"+plainsig
  
print "%s: Decrypted signature: %s"%(imagepath,hexbytes(plainsig))

#-------------------- Validate decrypted signature -------------------------------------

# https://blitter.net/blog/2019/05/04/exploring-the-pippin-roms-part-7-a-lot-to-digest/
#Decrypted signature
#  2  The number one
#  8  Bunch of 0xff
#  1  Zero
# 13  30 20 30 0c 06 08 2a 86 48 86 f7 0d 02
#  1  MD who? "5"
#  4  05 00 04 10
# 16  MD5 of message (through 15-byte Padding)

one=plainsig[0:2]
effs=plainsig[2:10]
zero=plainsig[10:11]
mystery1=plainsig[11:24]
mdwho=plainsig[24:25]
mystery2=plainsig[25:29]
signedhash=plainsig[29:45]

if one!="\x00\x01":
  print "%s: Expected \\0\\1, found %r"%(imagepath,one)
if effs!="\xff\xff\xff\xff\xff\xff\xff\xff":
  print "%s: Expected 8 of 0xff, found %r"%(imagepath,effs)
if zero!="\x00":
  print "%s: Expected a single NUL, found %r"%(imagepath,zero)
if mystery1!="\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02":
  print "%s: Expected 13 mysterious constant bytes, found %r (see 'mystery1' in check.py)"%(imagepath,mystery1)
if mdwho!="\x05":
  print "%s: Expected '5' as in 'MD5', found %r"%(imagepath,mdwho)
if mystery2!="\x05\x00\x04\x10":
  print "%s: Expected 4 mysterious constant bytes, found %r (see 'myster2' in check.py)"%(imagepath,mystery2)
  
# and the one that matters:
if signedhash!=messagehash:
  print "!!! HASH MISMATCH IN %s"%(imagepath,)
  print "     Hashed from PAF content: %s"%(hexbytes(messagehash),)
  print "Decrypted from PAF signature: %s"%(hexbytes(signedhash),)
else:
  print "%s: PippinAuthenticationFile signature checks out. This should boot!"%(imagepath,)
  
if len(src)<64*1024*1024 or chunkc<512:
  print "!!! WARNING !!! This disc might be too small to pass authentication. Try padding to 512 auth chunks and 64 MB gross size."
  print "Current chunk count: %d"%(chunkc,)
  print "Current gross size: %d MB"%(len(src)/(1024*1024),)
