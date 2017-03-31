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

#def factorial(n):
#    print("factorial has been called with n = " + str(n))
#    if n == 1:
#        return 1
#    else:
#        res = n * factorial(n-1)
#        print("intermediate result for ", n, " * factorial(" ,n-1, "): ",res)
#        return res	
#print(factorial(5))


def getListOfAllFunctionsEAs(listOfAllFunctionsEAs):
	functionNumber = 0
	print("")
	for f in Functions(SegStart(ea),SegEnd(ea)):
		name = GetFunctionName(f)	
		#end = GetFunctionAttr(f, FUNCATTR_END)

		print("Function[%d] %s, Address[0x%x]" % (functionNumber, name, f))
		functionNumber += 1
		listOfAllFunctionsEAs.append(f)



# recursively explore all 
def recursivelyExploreAllSpecificFunctionsThroughExport(exportName, depth, ea, listOfSpecificFunctions):
	functionNumber = 0
	for f in Functions(SegStart(ea),SegEnd(ea)):
		name = GetFunctionName(f)
		
		#end = GetFunctionAttr(f, FUNCATTR_END)

		print("Export[%d] %s: Function[%d] %s, Address[0x%x]" % (depth, exportName, functionNumber, name, f))
		functionNumber += 1
	print("")
	
	
#def processFunction(targetedFuncEA, currentFuncEA):

	






# list of specific functions which we are searching for
listOfAllTargetedFunctionsNames = ["strcpy", "sprintf", "wcsncpy", "swprintf"]
listOfAllFunctionsEAs = []
listOfAllExportsEAs = []
		
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
	print("targetedFuncName: %s") % targetedFuncName


print("\nlistOfAllFunctionsEAs")
print [hex(functionEA) for functionEA in listOfAllFunctionsEAs]

print("\nlistOfAllExports")
print [hex(ExportEA) for ExportEA in listOfAllExportsEAs]