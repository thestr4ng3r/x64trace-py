
import struct
import json
import enum
import os
from functools import reduce
from dataclasses import dataclass

from . import registers


MAX_MEMORY_OPERANDS = 32

class TraceParseError(Exception):
	pass

class TraceFileError(Exception):
	pass

def _read_exactly(f, size):
	b = f.read(size)
	if len(b) < size:
		raise TraceParseError("Unexpected EOF")
	return b

def _seek_forward_exactly(f, offset):
	dst = f.tell() + offset
	n = f.seek(dst)
	if n != dst:
		raise TraceParseError("Unexpected EOF")


def _read_struct(f, s):
	b = _read_exactly(f, s.size)
	return s.unpack(b)

def _json_get(json_data, key, possible_values):
	if key not in json_data:
		raise TraceParseError("Missing {} key in json".format(key))
	val = json_data[key]
	if val not in possible_values:
		raise TraceParseError("Invalid value for {} in json".format(key))
	return val


class Arch(enum.Enum):
	X86 = "x86"
	X64 = "x64"


@dataclass
class MemoryAccess:
	address: int
	flags: bytes
	old: bytes
	new: bytes

	@property
	def is_write(self):
		return (self.flags & 1) == 0


class Trace:
	class Block:
		def __init__(self):
			self.thread_id = None
			self.opcode = None
			self.registers = None
			self.mem = []

	def __init__(self, arch, path=None):
		self.arch = arch
		self.path = path
		self.blocks = []

	_header_struct = struct.Struct("<4sI")
	_thread_id_struct = struct.Struct("<I")

	@classmethod
	def load32(cls, f):
		return cls._load(f, 4)

	@classmethod
	def load64(cls, f):
		return cls._load(f, 8)

	@classmethod
	def loadf32(cls, filename):
		with open(filename, "rb") as f:
			return cls.load32(f)
	
	@classmethod
	def loadf64(cls, filename):
		with open(filename, "rb") as f:
			return cls.load64(f)

	@classmethod
	def loadf(cls, filename):
		_, ext = os.path.splitext(filename)
		ext = ext.lower()
		if ext == ".trace32":
			return cls.loadf32(filename)
		elif ext == ".trace64":
			return cls.loadf64(filename)
		else:
			raise TraceFileError("File type not recognized")

	@classmethod
	def _load(cls, f, ptr_sz):
		assert ptr_sz in [4, 8]

		(magic, hdr_info_sz) = _read_struct(f, cls._header_struct)
		if magic != b"TRAC":
			raise TraceParseError("Invalid Magic")
		if hdr_info_sz > 16384:
			raise TraceParseError("Header info is too big")

		json_data = _read_exactly(f, hdr_info_sz).decode("utf-8")
		json_data = json.loads(json_data)

		if "ver" not in json_data:
			raise TraceParseError("Version not specified in file")
		version = json_data["ver"]
		if version != 1:
			raise TraceParseError("Version not supported")

		arch = Arch(_json_get(json_data, "arch", [e.value for e in Arch]))
		_json_get(json_data, "compression", [""])

		path = None
		if "path" in json_data:
			path = json_data["path"]
			if not isinstance(path, str):
				raise TraceParseError("Invalid path entry in json")

		hash_value = None
		if "hashAlgorithm" in json_data:
			hash_alg = json_data["hashAlgorithm"]
			if hash_alg == "murmurhash" and "hash" in json_data:
				hash_value_str = json_data["hash"]
				if isinstance(hash_value_str, str):
					hash_value = int(hash_value_str, 0)

		trace = Trace(arch, path)

		# read blocks
		thread_id = None
		regdump_cls = registers.RegDump64 if ptr_sz == 8 else registers.RegDump32
		regdump_words = (regdump_cls.size + 4) // ptr_sz 
		regdump = bytearray(b"\x00" * (regdump_words * ptr_sz))
		while True:
			block_type = f.read(1)
			if len(block_type) != 1: # eof
				break
			block_type = block_type[0]
			if block_type != 0:
				raise TraceParseError("Unsupported block type")

			block = Trace.Block()

			changed_count_flags = _read_exactly(f, 3)

			# thread id
			if (changed_count_flags[2] & 0x80) != 0:
				last_thread_id = _read_struct(f, cls._thread_id_struct)[0]
			block.thread_id = last_thread_id

			# opcode
			opcode_sz = changed_count_flags[2] & 0x0f
			if opcode_sz <= 0:
				raise TraceParseError("Empty Opcode")
			opcode = _read_exactly(f, opcode_sz)
			block.opcode = opcode

			# registers
			regcount = changed_count_flags[0]
			#is_page_boundary = regcount == regdump_size
			if regcount > 0:
				if regcount > regdump_words:
					raise TraceParseError("Invalid Register Count")
				changed = _read_exactly(f, regcount)
				contents = _read_exactly(f, regcount * ptr_sz)
				last_pos = -1
				for i in range(regcount):
					last_pos += changed[i] + 1
					if last_pos >= regdump_words:
						raise TraceParseError("Out of bounds while reading registers")
					regdump[last_pos*ptr_sz:(last_pos+1)*ptr_sz] = contents[i*ptr_sz:(i+1)*ptr_sz]
			block.registers = regdump_cls(regdump[:regdump_cls.size])

			# memory
			memcount = changed_count_flags[1]
			if memcount > 0:
				if memcount > MAX_MEMORY_OPERANDS:
					raise TraceParseError("Too many memory changes")

				mem_flags = _read_exactly(f, memcount)
				mem_address = _read_exactly(f, ptr_sz * memcount)
				mem_old_content = _read_exactly(f, ptr_sz * memcount)

				for i in range(memcount):
					address = int.from_bytes(mem_address[i*ptr_sz:(i+1)*ptr_sz], byteorder="little")
					flags = mem_flags[i]
					old = mem_old_content[i*ptr_sz:(i+1)*ptr_sz]
					if (flags & 1) == 0:
						new = _read_exactly(f, ptr_sz)
					else:
						new = old
					block.mem.append(MemoryAccess(address=address, flags=flags, old=old, new=new))

			trace.blocks.append(block)

		return trace


