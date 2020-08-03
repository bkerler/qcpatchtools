import sys
import os

def SCM_ATOMIC(svc, cmd, n):
 return (((((svc) << 10)|((cmd) & 0x3ff)) << 12) | (0x2 << 8) | 0x10 | (n & 0xf))

def main():
	v1=int(sys.argv[1],16)
	v2=int(sys.argv[2],16)
	val=SCM_ATOMIC(v1,v2,28)
	print(hex(val))
main()