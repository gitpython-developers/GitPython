"""Module with functions which are supposed to be as fast as possible"""

__all__ = ('tree_to_stream', 'tree_entries_from_data')

def tree_to_stream(entries, write):
	"""Write the give list of entries into a stream using its write method
	:param entries: **sorted** list of tuples with (binsha, mode, name)
	:param write: write method which takes a data string"""
	ord_zero = ord('0')
	bit_mask = 7			# 3 bits set
	
	for binsha, mode, name in entries:
		mode_str = ''
		for i in xrange(6):
			mode_str = chr(((mode >> (i*3)) & bit_mask) + ord_zero) + mode_str
		# END for each 8 octal value
		
		# git slices away the first octal if its zero
		if mode_str[0] == '0':
			mode_str = mode_str[1:]
		# END save a byte

		write("%s %s\0%s" % (mode_str, name, binsha)) 
	# END for each item


def tree_entries_from_data(data):
	"""Reads the binary representation of a tree and returns tuples of Tree items
	:param data: data block with tree data
	:return: list(tuple(binsha, mode, tree_relative_path), ...)"""
	ord_zero = ord('0')
	len_data = len(data)
	i = 0
	out = list()
	while i < len_data:
		mode = 0
		
		# read mode
		# Some git versions truncate the leading 0, some don't
		# The type will be extracted from the mode later
		while data[i] != ' ':
			# move existing mode integer up one level being 3 bits
			# and add the actual ordinal value of the character
			mode = (mode << 3) + (ord(data[i]) - ord_zero)
			i += 1
		# END while reading mode
		
		# byte is space now, skip it
		i += 1
		
		# parse name, it is NULL separated
		
		ns = i
		while data[i] != '\0':
			i += 1
		# END while not reached NULL
		name = data[ns:i]
		
		# byte is NULL, get next 20
		i += 1
		sha = data[i:i+20]
		i = i + 20
		
		out.append((sha, mode, name))
	# END for each byte in data stream
	return out
