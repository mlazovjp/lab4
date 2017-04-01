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
def processFunction(targetedFuncName, currentFuncEA, listOfAllExportsEAs):

	listOfFunctionsEAsCallingThisFunction = []
	tempListOfFunctionsEAsCallingThisFunction = []
	currentFuncName = GetFunctionName(currentFuncEA)
	
	
	#listOfFunctionsEAsCallingThisFunction = CodeRefsTo(SegStart(currentFuncEA), 0) # I need this to return ea of the function this head exists in
	tempListOfFunctionsEAsCallingThisFunction = CodeRefsTo(currentFuncEA, 0) # I need this to return ea of the function this head exists in
	
	for item in tempListOfFunctionsEAsCallingThisFunction:
		listOfFunctionsEAsCallingThisFunction.append(GetFchunkAttr(item, FUNCATTR_START))
	
	
	#for fixEA in listOfFunctionsEAsCallingThisFunction:
	#	fixEA = GetFchunkAttr(fixEA, FUNCATTR_START)
	
	print("\n   targetedFuncName is %s, currentFuncName %s [0x%x]:") % (targetedFuncName, currentFuncName, currentFuncEA)
	
	if not listOfFunctionsEAsCallingThisFunction:
		print("   No cross references found for %s [0x%x]") % (currentFuncName, currentFuncEA)
		print("   %s starting address[0x%x]") % (currentFuncName, GetFchunkAttr(currentFuncEA, FUNCATTR_START))
		print("")
		return
	
	print("   Cross references found for %s") % currentFuncName
	print("   %s") % listOfFunctionsEAsCallingThisFunction
	#print [hex(ea) for ea in listOfFunctionsEAsCallingThisFunction]
	print("   %s starting address[0x%x]") % (currentFuncName, GetFchunkAttr(currentFuncEA, FUNCATTR_START))
	#print("")
	
	# continue processing
	for fctfEA in listOfFunctionsEAsCallingThisFunction:
	
		# reset boolean ... no export found in this pass
		exportFound = False
		
		# cycle through list of all exports effeactive addresses
		for anExportEA in listOfAllExportsEAs:
		
			if not fctfEA:
				print("     not fctfEA")
				
			else:
				print("     fctfEA (0x%x") % fctfEA
		
				# does fctfEA == effective address of the export we are evaluating?
				if fctfEA == anExportEA:
					exportFound = True
					print("   fctfEA (0x%x) == anExportEA (0x%x)") % (fctfEA, anExportEA)
					print("   %s:%s") % (GetFunctionName(anExportEA), targetedFuncName)
				else:
					print("   fctfEA (0x%x) <> anExportEA (0x%x)") % (fctfEA, anExportEA)
				
				if exportFound == False:
					processFunction(targetedFuncName, fctfEA, listOfAllExportsEAs)
			#nextEA = GetFchunkAttr(fctfEA, FUNCATTR_START)
			
			#if not nextEA:
			#	print("     No result for GetFchunkAttr(0x%x, FUNCATTR_START)\n" % fctfEA)
			#else:
			#	print("     Result for GetFchunkAttr(0x%x, FUNCATTR_START): 0x%x\n" % (fctfEA, nextEA))
			#	processFunction(targetedFuncName, GetFchunkAttr(fctfEA, FUNCATTR_START), listOfAllExportsEAs)
			
		

		
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
			print("   \nFound targetedFuncName %s in current funcName %s") % (targetedFuncName, funcName)
			
			# we now know the effective address of one of our targeted functions! e.g. strcpy
			processFunction(targetedFuncName, funcEA, listOfAllExportsEAs)
		


print("\nlistOfAllFunctionsEAs")
print [hex(functionEA) for functionEA in listOfAllFunctionsEAs]

print("\nlistOfAllExports")
print [hex(ExportEA) for ExportEA in listOfAllExportsEAs]
