import binascii
import os
import errno

#{ Routines

hex_to_bin = binascii.a2b_hex
bin_to_hex = binascii.b2a_hex

def to_hex_sha(sha):
	""":return: hexified version  of sha"""
	if len(sha) == 40:
		return sha
	return bin_to_hex(sha)
	
def to_bin_sha(sha):
	if len(sha) == 20:
		return sha
	return hex_to_bin(sha)

# errors
ENOENT = errno.ENOENT

# os shortcuts
exists = os.path.exists
mkdir = os.mkdir
isdir = os.path.isdir
rename = os.rename
dirname = os.path.dirname
join = os.path.join
read = os.read
write = os.write
close = os.close


#} END Routines


