# Reverse Engineering
# Lab 4, script 1
# Jeremy Mlazovsky

print "Detect MD5 Hash Table.\n"

MD5HashFound = False
#MD5Hash01 = 0x65746e45		#Ente (found correctly in password1.exe)

MD5Hash01 = 0x78a46ad7		#0xd76aa478
MD5Hash02 = 0x56b7c7e8		#0xe8c7b756
MD5Hash03 = 0xdb702024		#0x242070db
MD5Hash04 = 0xeecebdc1		#0xc1bdceee

# For each of the segments
for seg in Segments():

	# if one of the precomputed MD5 Hash Table values was alerady detected, then don't bother ...
	if MD5HashFound == False:
		# For each of the defined elements
		for head in Heads(seg, SegEnd(seg)):
		
			flag = GetFlags(head)
			
			# we only want to search in .data section
			if isData(flag):

				# get the DWORD at this effective address
				aDWord = Dword(head)

				#compare that DWORD to precomputed MD5 Hash Table values
				if aDWord == MD5Hash01 or aDWord == MD5Hash02 or aDWord == MD5Hash03 or aDWord == MD5Hash04:
					print "MD5 Constants present."
					MD5HashFound = True
					break				# exit this iteration of the for loop

			
if MD5HashFound == False:
	print "No MD5 constants are present."