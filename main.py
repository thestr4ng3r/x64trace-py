
import x64trace
import sys

with open(sys.argv[1], "rb") as f:
	t = x64trace.Trace.load(f)
print(t)
