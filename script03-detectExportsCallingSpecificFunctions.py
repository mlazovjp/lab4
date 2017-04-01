# Reverse Engineering
# Lab 4, script 3
# Jeremy Mlazovsky


from idaapi import *

ea = BeginEA()

print "Determine if any exported functions call a function (which may call a function ..."
print "that is in the list of functions below.  If an exported function calls a function"
print "and three calls deep into that function a call to a strcpy is placed, print the name of"
print "the exported function and the function from the list that is called."
print "These functions are:"
print "  strcpy"
print "  sprintf"
print "  strncpy"
print "  wcsncpy"
print "  swprint\n"
print "Results are in format:"
print "<function name>:<function called>\n"


# list of specific functions which we are searching for
listOfAllTargetedFunctionsNames = ["strcpy", "sprintf", "wcsncpy", "swprintf"]
listOfAllFunctionsEAs = []
listOfAllExportsEAs = []


def getListOfAllFunctionsEAs(listOfAllFunctionsEAs):
	functionNumber = 0
	print("")
	for f in Functions(SegStart(ea),SegEnd(ea)):
		name = GetFunctionName(f)
		#end = GetFunctionAttr(f, FUNCATTR_END)

		print("Function[%d] %s, Address[0x%x]" % (functionNumber, name, f))
		functionNumber += 1
		listOfAllFunctionsEAs.append(f)
	

# recursively traverse calling functions and hope the trail ends with an export function
def processFunction(targetedFuncEA, currentFuncEA, listOfAllExportsEAs):
	listOfFunctionsEAsCallingThisFunction.append( CodeRefsTo(currentFuncEA, 0) )
	print("targetedFuncEA[%x], currentFuncEA[%x]:") % (targetedFuncEA, currentFuncEA)
	print[hex(ea) for ea in listOfFunctionsEAsCallingThisFunction]
	
	# if no functions call this function ....
	#if not listOfFunctionsEAsCallingThisFunction:
	#	return
	
	# continue processing
	#for fctfEA in listOfFunctionsEAsCallingThisFunction:
	
		# reset boolean ... no export found in this pass
	#	exportFound = False
		
		# cycle through list of all exports
	#	for anExport in listOfAllExportsEAs:
		
			# get the name of the export
	#		exportName = (GetFunctionName(anExport))
			
			# get name of the function
	#		fctfName = GetFunctionName(fctfEA)
			
			# compare name of the current "function calling this function" to the list of names of exports
			# we haev to do some trickery to parse the "clean" version of the function
	#		if exportName.find("_strcpy") > -1:
	#			if len(exportName) == (exportName.find("_strcpy") + len("_strcpy")):		# nothing after "_strcpy"
	#				exportFound = True
	#				print("%s:strcpy") % exportName
	#				continue
					
	#		elif exportName.find("_sprintf") > -1:
	#			if len(exportName) == (exportName.find("_sprintf") + len("_sprintf")):		# nothing after "_sprintf"
	#				exportFound = True
	#				print("%s:sprintf") % exportName
	#				continue
					
	#		elif exportName.find("_strncpy") > -1:
	#			if len(exportName) == (exportName.find("_strncpy") + len("_strncpy")):		# nothing after "_strncpy"
	#				exportFound = True
	#				print("%s:strncpy") % exportName
	#				continue
					
	#		elif exportName.find("_wcsncpy") > -1:
	#			if len(exportName) == (exportName.find("_wcsncpy") + len("_wcsncpy")):		# nothing after "_wcsncpy"
	#				exportFound = True
	#				print("%s:wcsncpy") % exportName
	#				continue
					
	#		elif exportName.find("_swprintf") > -1:
	#			if len(exportName) == (exportName.find("_swprintf") + len("_swprintf")):	# nothing after "_swprintf"
	#				exportFound = True
	#				print("%s:swprintf") % exportName
	#				continue
					
					
	#		if exportFound == False:
	#			processFunction(targetedFuncEA, fctfEA, listOfAllExportsEAs)


		
# generate list of effective addresses for all exports
for i in range(GetEntryPointQty()):
	ord = GetEntryOrdinal(i)
	if ord == 0:
		continue
	addr = GetEntryPoint(ord)
	#exportName = (GetFunctionName(ea))
	print("Export[%s]:Address[%x]" % (GetFunctionName(addr), addr))
	listOfAllExportsEAs.append(addr)

# generate list of effective addresses for all functions
getListOfAllFunctionsEAs(listOfAllFunctionsEAs)

# iterate through all targeted function names ...
for targetedFuncName in listOfAllTargetedFunctionsNames:

	print("")
	
	# parse each function name and compare it to list of targeted function names
	# if a match, then we traverse backwards from calling function accordingly, looking for export function if it exists
	for funcEA in listOfAllFunctionsEAs:
	
		funcName = GetFunctionName(funcEA)
		print("Comparing targetedFuncName %s to funcName %s") % (targetedFuncName, funcName)
		
		if funcName.find(targetedFuncName) > -1:
			print("   Found targetedFuncName %s in current funcName %s") % (targetedFuncName, funcName)
		
		
	
	
	#print("targetedFuncName: %s") % targetedFuncName
	#processFunction(targetedFuncEA, currentFuncEA, listOfAllExportsEAs)


print("\nlistOfAllFunctionsEAs")
print [hex(functionEA) for functionEA in listOfAllFunctionsEAs]

print("\nlistOfAllExports")
print [hex(ExportEA) for ExportEA in listOfAllExportsEAs]