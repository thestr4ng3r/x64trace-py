
import struct
import json
import enum


header_struct = struct.Struct("<4sI")


class TraceParseError(Exception):
	pass

def _read_exactly(f, size):
	b = f.read(size)
	if len(b) < size:
		raise TraceParseError("Unexpected EOF")
	return b

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
	def __init__(self, arch, path):
		self.arch = arch
		self.path = path
	
	@staticmethod
	def load(f):
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


