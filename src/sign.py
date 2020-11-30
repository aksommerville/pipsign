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
  p+=pafp
  return (ord(src[p])<<24)|(ord(src[p+1])<<16)|(ord(src[p+2])<<8)|ord(src[p+3])
  
def wr32(n):
  return chr(n>>24)+chr((n>>16)&0xff)+chr((n>>8)&0xff)+chr(n&0xff)

#------------------ Locate PippinAuthenticationFile -----------------------
    
# Locate the PAF wherever we want and write that location into the MDB.
# First determine the PAF size.
chunk_size=128*1024
chunkc=len(src)/chunk_size
pafsize=80+16*chunkc+64
pafsize=(pafsize+511)&~511 # round the whole thing up to 512
lesser_chunkc=chunkc
chunkc=(pafsize-64-80)/16 # ...might create some dummy chunks in the PAF
pafp=(len(src)&~511)-pafsize
    
print "Creating PAF at 0x%08x, length %d"%(pafp,pafsize)

pafblock=pafp/512
src=src[:0x5f8]+wr32(pafblock)+wr32(pafsize)+src[0x600:]

src=src[:pafp]+"\0"*pafsize+src[pafp+pafsize:]

#--------------------- Hash each chunk --------------------------------

paf=wr32(80+chunkc*16+15)
paf+=wr32(0) # Auth file version
paf+=COPYRIGHT
paf+=wr32(131072) # Chunk size, 128 MB
paf+=wr32(lesser_chunkc)

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

toc=""
for chunkp in xrange(chunkc):
  physical_offset=chunkp*chunk_size
  # Cleanse the MDB.
  # The blocks under the PAF are already zeroed.
  if chunkp==0:
    chunkhash=md5.md5(cleanse_mdb(src[physical_offset:physical_offset+chunk_size])).digest()
  else:
    chunkhash=md5.md5(src[physical_offset:physical_offset+chunk_size]).digest()
  toc+=chunkhash
  
paf+=toc
paf+="\0"*15
  
#------------------------ Assemble PippinAuthenticationFile Message part and hash it -------------

messagehash=md5.md5(paf).digest()

# https://blitter.net/blog/2019/05/04/exploring-the-pippin-roms-part-7-a-lot-to-digest/
#Decrypted signature
#  2  The number one
#  8  Bunch of 0xff
#  1  Zero
# 13  30 20 30 0c 06 08 2a 86 48 86 f7 0d 02
#  1  MD who? "5"
#  4  05 00 04 10
# 16  MD5 of message (through 15-byte Padding)

plainsig="\x00\x01"
plainsig+="\xff\xff\xff\xff\xff\xff\xff\xff"
plainsig+="\0"
plainsig+="\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02" # TODO What is this?
plainsig+="\x05"
plainsig+="\x05\x00\x04\x10" # TODO This too
plainsig+=messagehash
if len(plainsig)!=45: raise Exception("plain signature length %d"%(len(plainsig),))

# Verify process with known signature block.
#plainsig="\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x30\x20\x30\x0C\x06"
#plainsig+="\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05\x05\x00\x04\x10\xAE\x1A\xEC"
#plainsig+="\xAE\xA4\xC5\x11\x68\x2E\x38\x7D\xD1\x48\xF0\x55\xC2"
#...verified :)

#--------------- Now the fireworks: Encrypt (plainsig) with our stolen RSA key ---------------

d=0x011CD3ADE7998667D6E9E21711DBEC3307B60E4D6D032620775DDB9B3B64CF22B20E4AF32F0740EEB06F85F2A01D
e=0x10001
p=0x0F2D25BF3C5B7028726E49753FD562671137389451EFD7
q=0x0ED1475DE1924128592C4B3E474E5FC1231F1BAFA0D82B
n=p*q

# Plaintext signature as a long
plainsign=0
for ch in plainsig:
  plainsign<<=8
  plainsign|=ord(ch)

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
encsign=right_to_left(plainsign,d,n)

# Encrypted signature as a string
encsig=""
while encsign>0:
  encsig=chr(encsign&0xff)+encsig
  encsign>>=8
while len(encsig)<len(plainsig):
  encsig="\0"+encsig

def hexbytes(src):
  return ''.join(map(lambda ch:"%02x"%(ord(ch),),src))
print " INPUT: %s"%(hexbytes(plainsig),)
print "OUTPUT: %s"%(hexbytes(encsig),)

if len(encsig)!=45: raise Exception("Signature length %d, expected 45"%(len(encsig),))

#------------------------- Put it all together and replace PippinAuthenticationFile ------------

# Rewrite the whole thing -- we have modified MDB in addition to the PAF at the end.
paf+="\x2d\0\0\0"+encsig
src=src[:pafp]+paf+src[pafp+pafsize:]
open(imagepath,"w").write(src)

print "%s: Rewrote PippinAuthenticationFile"%(imagepath,)

if len(src)<64*1024*1024 or chunkc<512:
  # TODO Once we're confident this is accurate, change 'mkfs' to add a pad file automatically.
  print "!!! WARNING !!! This disc might be too small to pass authentication. Try padding to 512 auth chunks and 64 MB gross size."
  print "Current chunk count: %d"%(chunkc,)
  print "Current gross size: %d MB"%(len(src)/(1024*1024),)
