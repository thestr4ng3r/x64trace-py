
import struct
from abc import ABC

class RegisterUnpackError(Exception):
	pass

"""
typedef struct
{
    bool c;
    bool p;
    bool a;
    bool z;
    bool s;
    bool t;
    bool i;
    bool d;
    bool o;
} FLAGS;
"""
class Flags:
	_struct = struct.Struct("<9?")

	size = _struct.size

	def __init__(self, data):
		(self.c,
		self.p,
		self.a,
		self.z,
		self.s,
		self.t,
		self.i,
		self.d,
		self.o) = self._struct.unpack(data)

"""
typedef struct
{
    bool FZ;
    bool PM;
    bool UM;
    bool OM;
    bool ZM;
    bool IM;
    bool DM;
    bool DAZ;
    bool PE;
    bool UE;
    bool OE;
    bool ZE;
    bool DE;
    bool IE;

    unsigned short RC;
} MXCSRFIELDS;
"""
class MXCSRFields:
	_struct = struct.Struct("<14?H")

	size = _struct.size

	def __init__(self, data):
		(self.FZ,
		self.PM,
		self.UM,
		self.OM,
		self.ZM,
		self.IM,
		self.DM,
		self.DAZ,
		self.PE,
		self.UE,
		self.OE,
		self.ZE,
		self.DE,
		self.IE,
		self.RC) = self._struct.unpack(data)


"""
typedef struct
{
    bool B;
    bool C3;
    bool C2;
    bool C1;
    bool C0;
    bool ES;
    bool SF;
    bool P;
    bool U;
    bool O;
    bool Z;
    bool D;
    bool I;

    unsigned short TOP;

} X87STATUSWORDFIELDS;
"""
class X87StatusWordFields:
	_struct = struct.Struct("<13?xH")

	size = _struct.size

	def __init__(self, data):
		(self.B,
		self.C3,
		self.C2,
		self.C1,
		self.C0,
		self.ES,
		self.SF,
		self.P,
		self.U,
		self.O,
		self.Z,
		self.D,
		self.I,
		self.TOP) = self._struct.unpack(data)

"""
typedef struct
{
    bool IC;
    bool IEM;
    bool PM;
    bool UM;
    bool OM;
    bool ZM;
    bool DM;
    bool IM;

    unsigned short RC;
    unsigned short PC;

} X87CONTROLWORDFIELDS;
"""
class X87ControlWordFields:
	_struct = struct.Struct("<8?2H")

	size = _struct.size

	def __init__(self, data):
		(self.IC,
		self.IEM,
		self.PM,
		self.UM,
		self.OM,
		self.ZM,
		self.DM,
		self.IM,
		self.RC,
		self.PC) = self._struct.unpack(data)

"""
typedef struct DECLSPEC_ALIGN(16) _XMMREGISTER
{
    ULONGLONG Low;
    LONGLONG High;
} XMMREGISTER;
"""
class XmmRegister:
	_struct = struct.Struct("<Qq")

	size = _struct.size

	def __init__(self, data):
		(self.Low,
		self.High) = self._struct.unpack(data)


"""
typedef struct
{
    XMMREGISTER Low; //XMM/SSE part
    XMMREGISTER High; //AVX part
} YMMREGISTER;
"""
class YmmRegister:
	size = 2 * XmmRegister.size

	def __init__(self, data):
		self.Low = XmmRegister(data[:XmmRegister.size])
		self.High = XmmRegister(data[XmmRegister.size:])

"""
typedef struct
{
    BYTE    data[10];
    int     st_value;
    int     tag;
} X87FPUREGISTER;
"""
class X87FPURegister:
	_struct = struct.Struct("<10sxxii")
	
	size = _struct.size

	def __init__(self, data):
		(self.data,
		self.st_value,
		self.tag) = self._struct.unpack(data)

"""
typedef struct
{
    WORD   ControlWord;
    WORD   StatusWord;
    WORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    DWORD   Cr0NpxState;
} X87FPU;
"""
class X87FPU:
	_struct = struct.Struct("<HHHxxIIIII")

	size = _struct.size

	def __init__(self, data):
		(self.ControlWord,
		self.StatusWord,
		self.TagWord,
		self.ErrorOffset,
		self.ErrorSelector,
		self.DataOffset,
		self.DataSelector,
		self.Cr0NpxState) = self._struct.unpack(data)



"""
typedef struct
{
    ULONG_PTR cax;
    ULONG_PTR ccx;
    ULONG_PTR cdx;
    ULONG_PTR cbx;
    ULONG_PTR csp;
    ULONG_PTR cbp;
    ULONG_PTR csi;
    ULONG_PTR cdi;
#ifdef _WIN64
    ULONG_PTR r8;
    ULONG_PTR r9;
    ULONG_PTR r10;
    ULONG_PTR r11;
    ULONG_PTR r12;
    ULONG_PTR r13;
    ULONG_PTR r14;
    ULONG_PTR r15;
#endif //_WIN64
    ULONG_PTR cip;
    ULONG_PTR eflags;
    unsigned short gs;
    unsigned short fs;
    unsigned short es;
    unsigned short ds;
    unsigned short cs;
    unsigned short ss;
    ULONG_PTR dr0;
    ULONG_PTR dr1;
    ULONG_PTR dr2;
    ULONG_PTR dr3;
    ULONG_PTR dr6;
    ULONG_PTR dr7;
    BYTE RegisterArea[80];
    X87FPU x87fpu;
    DWORD MxCsr;
#ifdef _WIN64
    XMMREGISTER XmmRegisters[16];
    YMMREGISTER YmmRegisters[16];
#else // x86
    XMMREGISTER XmmRegisters[8];
    YMMREGISTER YmmRegisters[8];
#endif
} REGISTERCONTEXT;
"""
class RegisterContext64:
	_struct_0 = struct.Struct("<18Q6H4x6Q80s")
	_struct_1 = struct.Struct("<I")

	size = _struct_0.size \
			+ X87FPU.size \
			+ _struct_1.size \
			+ XmmRegister.size * 16 \
			+ YmmRegister.size * 16

	def __init__(self, data):
		if len(data) != self.size:
			raise RegisterUnpackError(f"Got {len(data)} bytes, but expected {self.size}")
		(self.cax,
		self.ccx,
		self.cdx,
		self.cbx,
		self.csp,
		self.cbp,
		self.csi,
		self.cdi,
		self.r8,
		self.r9,
		self.r10,
		self.r11,
		self.r12,
		self.r13,
		self.r14,
		self.r15,
		self.cip,
		self.eflags,
		self.gs,
		self.fs,
		self.es,
		self.ds,
		self.cs,
		self.ss,
		self.dr0,
		self.dr1,
		self.dr2,
		self.dr3,
		self.dr6,
		self.dr7,
		self.RegisterArea) = self._struct_0.unpack(data[:self._struct_0.size])
		data = data[self._struct_0.size:]
		(self.MxCsr,) = self._struct_1.unpack(data[:self._struct_1.size])
		data = data[self._struct_1.size:]
		self.XmmRegisters = []
		for i in range(8):
			self.XmmRegisters.append(XmmRegister(data[:XmmRegister.size]))
			data = data[XmmRegister.size:]
		self.YmmRegisters = []
		for i in range(8):
			self.YmmRegisters.append(YmmRegister(data[:YmmRegister.size]))
			data = data[YmmRegister.size:]


class RegisterContext32:
	_struct_0 = struct.Struct("<10I6H6I80s")
	_struct_1 = struct.Struct("<I")

	size = _struct_0.size \
			+ X87FPU.size \
			+ _struct_1.size \
			+ 4 \
			+ XmmRegister.size * 8 \
			+ YmmRegister.size * 8

	def __init__(self, data):
		if len(data) != self.size:
			raise RegisterUnpackError(f"Got {len(data)} bytes, but expected {self.size}")
		(self.cax,
		self.ccx,
		self.cdx,
		self.cbx,
		self.csp,
		self.cbp,
		self.csi,
		self.cdi,
		self.cip,
		self.eflags,
		self.gs,
		self.fs,
		self.es,
		self.ds,
		self.cs,
		self.ss,
		self.dr0,
		self.dr1,
		self.dr2,
		self.dr3,
		self.dr6,
		self.dr7,
		self.RegisterArea) = self._struct_0.unpack(data[:self._struct_0.size])
		data = data[self._struct_0.size:]
		(self.MxCsr,) = self._struct_1.unpack(data[:self._struct_1.size])
		data = data[self._struct_1.size+4:]
		self.XmmRegisters = []
		for i in range(8):
			self.XmmRegisters.append(XmmRegister(data[:XmmRegister.size]))
			data = data[XmmRegister.size:]
		self.YmmRegisters = []
		for i in range(8):
			self.YmmRegisters.append(YmmRegister(data[:YmmRegister.size]))
			data = data[YmmRegister.size:]


"""
typedef struct
{
    REGISTERCONTEXT regcontext;
    FLAGS flags;
    X87FPUREGISTER x87FPURegisters[8];
    unsigned long long mmx[8];
    MXCSRFIELDS MxCsrFields;
    X87STATUSWORDFIELDS x87StatusWordFields;
    X87CONTROLWORDFIELDS x87ControlWordFields;
    // LASTERROR lastError;
    // LASTSTATUS lastStatus;
} REGDUMP;
"""
class RegDumpBase(ABC):
	register_context_cls: type

	_mmx_struct = struct.Struct("<8Q")

	@classmethod
	def _calc_size(cls, register_context_cls):
		return register_context_cls.size \
			+ Flags.size \
			+ 3 \
			+ 8 * X87FPURegister.size \
			+ 4 \
			+ cls._mmx_struct.size \
			+ MXCSRFields.size \
			+ X87StatusWordFields.size \
			+ X87ControlWordFields.size

	def __init__(self, data):
		if len(data) != self.size:
			raise RegisterUnpackError(f"Got {len(data)} bytes, but expected {self.size}")
		offset = 0

		self.regcontext = self.register_context_cls(data[:self.register_context_cls.size])
		offset += self.register_context_cls.size

		self.flags = Flags(data[offset:offset+Flags.size])
		offset += Flags.size
		offset += 3 # padding

		self.x87FPURegisters = []
		for i in range(8):
			self.x87FPURegisters.append(X87FPURegister(data[offset:offset+X87FPURegister.size]))
			offset += X87FPURegister.size
		offset += 4 # padding

		self.mmx = list(self._mmx_struct.unpack(data[offset:offset+self._mmx_struct.size]))
		offset += self._mmx_struct.size

		self.MxCsrFields = MXCSRFields(data[offset:offset+MXCSRFields.size])
		offset += MXCSRFields.size

		self.x87StatusWordFields = X87StatusWordFields(data[offset:offset+X87StatusWordFields.size])
		offset += X87StatusWordFields.size

		self.x87ControlWordFields = X87ControlWordFields(data[:X87ControlWordFields.size])


class RegDump64(RegDumpBase):
	register_context_cls = RegisterContext64
	size = RegDumpBase._calc_size(register_context_cls)

class RegDump32(RegDumpBase):
	register_context_cls = RegisterContext32
	size = RegDumpBase._calc_size(register_context_cls)

