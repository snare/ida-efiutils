#!/usr/bin/env python
"""
te_loader.py

A TE image loader for IDA Pro. This was written specifically to load the SEC phase binaries from
Apple's EFI firmware so it has some specific behaviour to handle the segment types used in those
binaries, and is probably incomplete.

See the following URL for more info and the latest version:
https://github.com/snarez/ida-efiutils
"""

import struct
import sys
import os
try:
	from awesome_print import ap as pp
except:
	from pprint import pprint as pp
try:
	from idaapi import *
	from idautils import *
	from idc import *
	IN_IDA = True
except:
	print "not running in IDA?"
	IN_IDA = False

TE_MAGIC = "VZ"

SECTION_CLASSES = {
	b".text\0\0\0":	"CODE",
	b".data\0\0\0": "DATA",
	b".reloc\0\0": 	"DATA",
	b"_TEXT_RE": 	"CODE",
	b"_TEXT_PR": 	"CODE"
}

SECTION_MODES = {
	b"_TEXT_RE":	0,
}

class TEImage:
	"""
	typedef struct {
		UINT32 VirtualAddress;
		UINT32 Size;
	} EFI_IMAGE_DATA_DIRECTORY;

	typedef struct {
		UINT16                   Signature;
		UINT16                   Machine;
		UINT8                    NumberOfSections;
		UINT8                    Subsystem;
		UINT16                   StrippedSize;
		UINT32                   AddressOfEntryPoint;
		UINT32                   BaseOfCode;
		UINT64                   ImageBase;
		EFI_IMAGE_DATA_DIRECTORY DataDirectory[2];
	} EFI_TE_IMAGE_HEADER;
	"""

	def __init__(self, f):
		self.offset = f.tell()

		# read header
		(self.signature, self.machine, self.num_sections, self.subsystem, self.stripped_size,
			self.entry_point_addr, self.code_base,
			self.image_base) = struct.unpack("<HHBBHLLQ", f.read(24))
		(d1,d2,d3,d4) = struct.unpack("<IIII", f.read(16))
		self.data_dir = [(d1,d2),(d3,d4)]

		# read section table
		self.sections = []
		for i in range(0, self.num_sections):
			self.sections.append(TEImageSection(f))


class TEImageSection:
	"""
	typedef struct{
		char Name[8];
		int32 VirtualSize; 
		int32 VirtualAddress; 
		int32 SizeOfRawData;   
		int32 PointerToRawData;  
		int32 PointerToRelocations;  
		int32 PointerToLinenumbers; 
		int16 NumberOfRelocations;   
		int16 NumberOfLinenumbers; 
		int32 Characteristics;  
	} SectionTable;
	"""

	def __init__(self, f):
		self.offset = f.tell()

		# read header
		self.name = f.read(8)
		(self.virt_size, self.virt_addr, self.data_size, self.ptr_to_data, self.ptr_to_relocs,
			self.ptr_to_line_nums, self.num_relocs, self.num_line_nums,
			self.characteristics) = struct.unpack("<LLLLLLHHL", f.read(32))


# ida entry point
def accept_file(f, n):
	retval = 0

	if n == 0:
		f.seek(0)
		if f.read(2) == TE_MAGIC:
			retval = "TE executable"

	return retval

# ida entry point
def load_file(f, neflags, format):
	# parse header
	f.seek(0)
	te = TEImage(f)

	# load binary
	for sec in te.sections:
		seg_type = SECTION_CLASSES[sec.name] if sec.name in SECTION_CLASSES.keys() else "DATA"
		seg_mode = SECTION_MODES[sec.name] if sec.name in SECTION_MODES.keys() else 1
		f.file2base(f.tell(), sec.virt_addr, sec.virt_addr + sec.data_size, 1)
		add_segm(0, sec.virt_addr, sec.virt_addr + sec.virt_size, sec.name, seg_type)
		set_segm_addressing(get_segm_by_name(sec.name), seg_mode)

	add_entry(te.entry_point_addr, te.entry_point_addr, "_start", 1)

	return 1

# if run outside of ida, parse the image and print a summary
if __name__ == '__main__':
	if not IN_IDA:
		te = TEImage(open(sys.argv[1]))
		pp(te.__dict__)
		for i in range(0, len(te.sections)):
			print "section %i:" % i
			pp(te.sections[i].__dict__)


