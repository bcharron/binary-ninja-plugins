#!/usr/bin/python
#
# Binary Ninja plugin to parse Mach-O bundles. Depends on OSX's `nm` and the
# `macholib` python library.
#
# Copy to ~/Library/Application Support/Binary Ninja/plugins/
#
# 2016-12-23 bcharron@pobox.com

import macholib

from binaryninja import *
from macholib.MachO import MachO
from macholib.SymbolTable import SymbolTable
from subprocess import Popen, PIPE

SECTION_TYPES = {
        "__text"   : "PURE_CODE",
        "__bss"    : "ZEROFILL",
        "__common" : "ZEROFILL",
        "__data"   : "REGULAR"
}

MAGICS = {
        "MH_MAGIC" : 0xfeedface,
        "MH_CIGAM" : 0xcefaedfe,
        "MH_MAGIC_64" : 0xfeedfacf,
        "MH_CIGAM_64" : 0xcffaedfe
}

BUNDLE_TYPE = 8

PROT_FLAGS = {
	0x01 : SegmentReadable,
	0x02 : SegmentWritable,
	0x04 : SegmentExecutable
}

SECTION_FLAGS_XLAT = {
	macholib.mach_o.S_ATTR_PURE_INSTRUCTIONS : "PURE_CODE",
}

DEFAULT_BINJA_TYPE = "REGULAR"

def is_section(obj):
	return(isinstance(obj, macholib.mach_o.section_64) or isinstance(obj, macholib.mach_o.section))

def is_segment(obj):
	return(isinstance(obj, macholib.mach_o.segment_command_64) or isinstance(obj, macholib.mach_o.segment_command))

def get_binja_prot(flags):
	ret = 0

	for (bit, binja_val) in PROT_FLAGS.iteritems():
		if flags & bit > 0:
			ret |= binja_val

	return(ret)

class MachoParser(BinaryView):
	name = "MachoBundle"
	long_name = "MachO Bundle"

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)

        @classmethod
        def is_valid_for_data(self, data):
		#util.is_platform_file(bv.file)
		header = struct.unpack('>I', data.read(0, 4))[0]
		macho_type = struct.unpack('<I', data.read(12, 4))[0]

		for name, val in MAGICS.iteritems():
			if header == val and macho_type == BUNDLE_TYPE:
				return(True)

		return(False)

	def init(self):
		self.m = MachO(self.file.filename)

		self.arch = Architecture['x86_64']
		self.platform = Platform['mac-x86_64']

		log_error("Starting to parse..")

		#print m.headers
		#print dir(m)
		#print m.headers[0].__class__
		#symbols = SymbolTable(m.headers[0])

		self.register_all()

		log_info("All done.")

	def demangle(self, name):
		demangled_name = demangle_gnu3(self.arch, name)

		if demangled_name is not None:
			if len(demangled_name) >= 2 and demangled_name[1] is not None:
				demangled_name = demangled_name[1]

			if isinstance(demangled_name, list):
				if len(demangled_name) > 0:
					demangled_name = demangled_name[-1]
				else:
					# Attribute but no name
					demangled_name = name
		else:
			demangled_name = name

		return(demangled_name)

	def register_all(self):
		for header in self.m.headers:
			for cmd in header.commands:
				if isinstance(cmd[0], macholib.mach_o.load_command):
					(cmd_load, cmd_cmd, cmd_data) = cmd

					if is_segment(cmd_cmd):
						self.register_segment(cmd_cmd, cmd_data)
					else:
						log_info("Ignoring %s" % cmd_cmd)

		self.register_symbols()


	def register_symbols(self):
		proc = Popen(["nm", self.file.filename], stdout = PIPE)

		for line in proc.stdout:
			try:
				(addr, t, name) = line.strip().split()

				addr = int(addr, 16)

				demangled_name = self.demangle(name)

				if t == "t":
					log_info("%08X: function %s (%s)" % ( addr, name, demangled_name ))
					self.create_user_function(self.platform, addr)
					sym = Symbol(FunctionSymbol, addr, name, demangled_name)
					self.define_auto_symbol(sym)
				else:
					log_info("%08X: data symbol %s" % ( addr, name ))
					sym = Symbol(DataSymbol, addr, name, demangled_name)
					self.define_auto_symbol(sym)
			except ValueError, e:
				#print e.__class__
				#print line.rstrip()
				pass

	def register_segment(self, segment_cmd, cmd_data):
		segname = segment_cmd.segname.rstrip("\x00")

		log_info("Segment %s" % segname)

		prot = get_binja_prot(segment_cmd.initprot)
		self.add_auto_segment(start = segment_cmd.vmaddr, 
		                         length = segment_cmd.vmsize,
		                         data_offset = segment_cmd.fileoff,
		                         data_length = segment_cmd.filesize,
		                         flags = prot)

		sections = filter(lambda data: is_section(data), cmd_data)

		for section in sections:
			self.register_section(section)

	def register_section(self, section):
		sectname = section.sectname.strip("\x00")
		log_info("SECTION {sectname}  ADDR {addr} OFFSET {offset}  SIZE {size}  FLAGS {flags}".format(sectname = sectname, 
			addr = section.addr, offset = section.offset, size = section.size, flags = section.flags))
		is_code = section.flags & macholib.mach_o.S_ATTR_PURE_INSTRUCTIONS != 0

		binja_type = SECTION_TYPES.get(sectname.lower(), DEFAULT_BINJA_TYPE)

		self.add_auto_section(sectname, start = section.addr, length = section.size, align = section.align, type = binja_type)

MachoParser.register()
