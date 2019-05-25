
import struct
import json
import enum
from functools import reduce

from . import registers

header_struct = struct.Struct("<4sI")
thread_id_struct = struct.Struct("<I")


class TraceParseError(Exception):
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


class Trace:
	class Block:
		def __init__(self):
			self.thread_id = None
			self.opcode = None
			self.registers = None

	def __init__(self, arch, path=None):
		self.arch = arch
		self.path = path
		self.blocks = []

	@staticmethod
	def load32(f):
		return Trace._load(f, 4)

	@staticmethod
	def load64(f):
		return Trace._load(f, 8)

	@staticmethod
	def _load(f, ptr_sz):
		assert ptr_sz in [4, 8]

		(magic, hdr_info_sz) = _read_struct(f, header_struct)
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
		regdump_sz = 216 # TODO: calculate
		regdump_cls = registers.RegDump64 if ptr_sz == 8 else registers.RegDump32
		regdump = bytearray(b"\x00" * (regdump_sz * ptr_sz))
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
				last_thread_id = _read_struct(f, thread_id_struct)[0]
			block.thread_id = last_thread_id

			# opcode
			opcode_sz = changed_count_flags[2] & 0x0f
			if opcode_sz <= 0:
				raise TraceParseError("Empty Opcode")
			opcode = _read_exactly(f, opcode_sz)
			block.opcode = opcode

			# registers
			regcount = changed_count_flags[0]
			if regcount > 0:
				if regcount > regdump_sz:
					raise TraceParseError("Invalid Register Count")
				changed = _read_exactly(f, regcount)
				contents = _read_exactly(f, regcount * ptr_sz)
				last_pos = -1
				for i in range(regcount):
					last_pos += changed[i] + 1
					if last_pos >= regdump_sz:
						raise TraceParseError("Out of bounds while reading registers")
					regdump[last_pos*ptr_sz:(last_pos+1)*ptr_sz] = contents[i*ptr_sz:(i+1)*ptr_sz]
			block.registers = regdump_cls(regdump)

			memflags = _read_exactly(f, changed_count_flags[1])
			skip_offset = reduce(
				lambda a, i: a
					+ (2 if (memflags[i] & 1) != 0 else 3),
				range(changed_count_flags[1]),
				0)
			_seek_forward_exactly(f, skip_offset * ptr_sz)

			#is_page_boundary = regcount == regdump_size

			trace.blocks.append(block)

		return trace


