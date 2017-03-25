print "Detect MD5 Hash Table.\n"

MD5HashFound = False
#MD5Hash01 = 0x65746e45		#Ente

MD5Hash01 = 0x78a46ad7		#0xd76aa478
MD5Hash02 = 0x56b7c7e8		#0xe8c7b756
MD5Hash03 = 0xdb702024		#0x242070db
MD5Hash04 = 0xeecebdc1		#0xc1bdceee

# For each of the segments
for seg in Segments():

	if MD5HashFound == False:
		# For each of the defined elements
		for head in Heads(seg, SegEnd(seg)):
			flag = GetFlags(head)

			aDWord = Dword(head)
		
			#if aDWord == 0xd76ae479:
			#if aDWord == 0xec79e46a:
			if aDWord == MD5Hash01 or aDWord == MD5Hash02 or aDWord == MD5Hash03 or aDWord == MD5Hash04:
				#print "MD5 Hash %x Found at Address[%x]: aDWord: %x" % (MD5Hash01, head, aDWord)
				print "MD5 Constants present."
				MD5HashFound = True
				#break
		
			#print "Address[%x]: aDWord: %x" % (head, aDWord)

		
			#if isData(flag):
			#	print "Address[%x]: is Data" % (head)

			#elif isCode(flag):
			#	print "Address[%x]: is Code" % (head)
			#else:
			#	print "Address[%x]: Neither code nor data" % (head)
			
if MD5HashFound == False:
	print "No MD5 constants are present."