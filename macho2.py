#!/usr/bin/python

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

class MachoParser(object):
	def __init__(self, bv, filename):
		self.bv = bv
		self.filename = filename

		self.m = MachO(filename)

	def demangle(self, name):
		demangled_name = demangle_gnu3(self.bv.arch, name)

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
		proc = Popen(["nm", self.filename], stdout = PIPE)

		for line in proc.stdout:
			try:
				(addr, t, name) = line.strip().split()

				addr = int(addr, 16)

				demangled_name = self.demangle(name)

				if t == "t":
					log_info("%08X: function %s (%s)" % ( addr, name, demangled_name ))
					self.bv.create_user_function(self.bv.platform, addr)
					sym = Symbol(FunctionSymbol, addr, name, demangled_name)
					self.bv.define_auto_symbol(sym)
				else:
					log_info("%08X: data symbol %s" % ( addr, name ))
					sym = Symbol(DataSymbol, addr, name, demangled_name)
					self.bv.define_auto_symbol(sym)
			except ValueError, e:
				#print e.__class__
				#print line.rstrip()
				pass

	def register_segment(self, segment_cmd, cmd_data):
		segname = segment_cmd.segname.rstrip("\x00")

		log_info("Segment %s" % segname)
		#print "SEGMENT: %s" % segment_cmd.segname
		#print cmd_data

		prot = get_binja_prot(segment_cmd.initprot)
		self.bv.add_auto_segment(start = segment_cmd.vmaddr, 
		                         length = segment_cmd.vmsize,
		                         data_offset = segment_cmd.fileoff,
		                         data_length = segment_cmd.filesize,
		                         flags = prot)

		#segment = self.bv.get_segment_at(segment_cmd.vmaddr)
		
		sections = filter(lambda data: is_section(data), cmd_data)

		for section in sections:
			self.register_section(section)

	def register_section(self, section):
		sectname = section.sectname.strip("\x00")
		log_info("SECTION {sectname}  ADDR {addr} OFFSET {offset}  SIZE {size}  FLAGS {flags}".format(sectname = sectname, 
			addr = section.addr, offset = section.offset, size = section.size, flags = section.flags))
		is_code = section.flags & macholib.mach_o.S_ATTR_PURE_INSTRUCTIONS != 0
		#print "PURE_CODE: ", is_code

		binja_type = SECTION_TYPES.get(sectname.lower(), DEFAULT_BINJA_TYPE)

		#log_info("Section: %s" % sectname)
		self.bv.add_auto_section(sectname, start = section.addr, length = section.size, align = section.align, type = binja_type)

		#print dir(section)
		#print ""

def parse_file(bv):
	bv.arch = Architecture['x86_64']
	bv.platform = Platform['mac-x86_64']

	filename = bv.file.filename

	parser = MachoParser(bv, filename)

	log_error("Starting to parse..")

	#print m.headers
	#print dir(m)
	#print m.headers[0].__class__
	#symbols = SymbolTable(m.headers[0])

	parser.register_all()

	log_info("All done.")

PluginCommand.register("Parse Mach-O[2] Executable Bundle", "Parses a Mach-O executable bundle (identify functions and data)", parse_file)

log_info("name: %s" % __name__)
if __name__ == "__main__":
	class Fake():
		pass

	bv = Fake
	bv.file = Fake()
	bv.file.filename = "FCEU"
	parse_file(bv)

