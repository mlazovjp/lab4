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


# recursively explore all 
def recursivelyExploreAllSpecificFunctionsThroughExport(exportName, depth, ea, listOfSpecificFunctions):
	functionNumber = 0
	for f in Functions(SegStart(ea),SegEnd(ea)):
		name = GetFunctionName(f)
		
		#end = GetFunctionAttr(f, FUNCATTR_END)
		
		#recursivelyExploreAllSpecificFunctionsThroughExport(exportName, depth+1, f, listOfSpecificFunctions)
		print("Export[%d] %s: Function[%d] %s, Address[0x%x]" % (depth, exportName, functionNumber, name, f))
		functionNumber += 1
	print("")

# list of specific functions which we are searching for
listOfSpecificFunctions = ["strcpy", "sprintf", "wcsncpy", "swprintf"]
		
# cycle through all exports
for i in range(GetEntryPointQty()):
	ord = GetEntryOrdinal(i)
	if ord == 0:
		continue
	ea = GetEntryPoint(ord)
	exportName = (GetFunctionName(ea))
	recursivelyExploreAllSpecificFunctionsThroughExport(exportName, i, ea, listOfSpecificFunctions)
	
recursivelyExploreAllSpecificFunctionsThroughExport(exportName, 0, 0x40102D, listOfSpecificFunctions)
	