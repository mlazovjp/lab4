print "Detect MD5 Hash Table.\n"

# For each of the segments
for seg in Segments():
    # For each of the defined elements
    for head in Heads(seg, SegEnd(seg)):
        # If it's an instruction
        if isData(GetFlags(head)):
            print "Address[%x]: isData() = True" % (head)
			#if head
            #print "Detect MD5 Hash Table.\n"
            # Get the mnemonic and increment the count
            #mnem = GetMnem(head)
            #mnemonics[mnem] = mnemonics.get(mnem, 0)+1
            #if mnem == "cmp":
            #    MakeComm(head, "Compare instruction")
            #    SetColor(head, CIC_FUNC, 0x208020)
            #    SetColor(head, CIC_ITEM, 0x0F1567)
        elif isCode(GetFlags(head)):
            print "Address[%x]: isCode() = True" % (head)
        else:
		    print "Address[%x]: Neither code nor data" % (head)