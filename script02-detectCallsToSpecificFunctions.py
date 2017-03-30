# Reverse Engineering
# Lab 4, script 2
# Jeremy Mlazovsky


ea = BeginEA()

from idaapi import *

print "Detect whether or not a given file being analyzed makes calls to the following functions:"
print "  strcpy"
print "  sprintf"
print "  strncpy"
print "  wcsncpy"
print "  swprint\n"
print "Results are in format:"
print "<function name>:<address making the call>:<function called>\n"

for f in Functions(SegStart(ea),SegEnd(ea)):

	# get the end ea of the function
	end = GetFunctionAttr(f, FUNCATTR_END)
	
	for head in Heads(f, end):
		# If it's an instruction ... (basically redundant since functions are only in code)
		if isCode(GetFlags(head)):
			
			# Get the mnemonic for the current head
			mnem = GetMnem(head)

			if mnem == "call":				# using an important requires the mnemonic "call", so look for "call"
			
				theImport = ""				# reset the import to empty until we can set it properly
				theImportFound = False		# import was not found yet

				Disasm = GetDisasm(head)	# get the disassembly for this head so we can parse it
				
				# We are just going to hope that if we can find "strcpy", "sprintf", "strncpy", "wcsncpy", or "swprintf"
				# as a substring of the disassembly code here, then we are good *fingers crossed*
				if Disasm.find("_strcpy") > -1:
					if len(Disasm) == (Disasm.find("_strcpy") + len("_strcpy")):		# nothing after "_strcpy"
						theImport = "strcpy"
						theImportFound = True
				elif Disasm.find("_sprintf") > -1:
					if len(Disasm) == (Disasm.find("_sprintf") + len("_sprintf")):		# nothing after "_sprintf"
						theImport = "sprintf"
						theImportFound = True
				elif Disasm.find("_strncpy") > -1:
					if len(Disasm) == (Disasm.find("_strncpy") + len("_strncpy")):		# nothing after "_strncpy"
						theImport = "strncpy"
						theImportFound = True
				elif Disasm.find("_wcsncpy") > -1:
					if len(Disasm) == (Disasm.find("_wcsncpy") + len("_wcsncpy")):		# nothing after "_wcsncpy"
						theImport = "wcsncpy"
						theImportFound = True
				elif Disasm.find("_swprintf") > -1:
					if len(Disasm) == (Disasm.find("_swprintf") + len("_swprintf")):	# nothing after "_swprintf"
						theImport = "swprintf"
						theImportFound = True
				
				if theImportFound == True:								# one of the specified imports was found
					name = GetFunctionName(f)							# get the name of the current function
					print "%s:0x%08x:%s" % (name, head, theImport)		# output in the requested format