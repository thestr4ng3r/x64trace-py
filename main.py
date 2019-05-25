
import x64trace
import sys
import r2pipe

r = r2pipe.open("--")

def disassemble(b):
	return r.cmd(f"pi 1@x:{b.hex()}").strip()

with open(sys.argv[1], "rb") as f:
	t = x64trace.Trace.load32(f)
print(t)

for i, block in enumerate(t.blocks):
	print(f"{i}: {disassemble(block.opcode)}")

