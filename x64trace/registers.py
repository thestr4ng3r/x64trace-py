
import struct


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
	_struct = struct.Struct("<?????????")

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
	_struct = struct.Struct("<HHHIIIII")

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
	_struct_0 = struct.Struct("<QQQQQQQQQQQQQQQQQQHHHHHHQQQQQQ80s")
	_struct_1 = struct.Struct("<I")

	size = _struct_0.size \
			+ X87FPU.size \
			+ XmmRegister.size * 16 \
			+ YmmRegister.size * 16

	def __init__(self, data):
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
	_struct_0 = struct.Struct("<IIIIIIIIIIHHHHHHIIIIII80s")
	_struct_1 = struct.Struct("<I")

	size = _struct_0.size \
			+ X87FPU.size \
			+ XmmRegister.size * 8 \
			+ YmmRegister.size * 8

	def __init__(self, data):
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
		data = data[self._struct_1.size:]
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
class RegDump64:
	size = RegisterContext64.size \
			+ Flags.size

	def __init__(self, data):
		self.regcontext = RegisterContext64(data[:RegisterContext64.size])
		data = data[RegisterContext64.size:]
		self.flags = Flags(data[:Flags.size])


class RegDump32:
	size = RegisterContext32.size \
			+ Flags.size

	def __init__(self, data):
		self.regcontext = RegisterContext32(data[:RegisterContext32.size])
		data = data[RegisterContext32.size:]
		self.flags = Flags(data[:Flags.size])


