
# x64trace

This is a python library for loading traces (.trace32, .trace64) created with [x64dbg](https://x64dbg.com).

## Install

```
pip install x64trace
```

## Example Usage

```python
import x64trace

t = x64trace.Trace.loadf("MyTrace.trace64")

for block in t.blocks:
	print("rax: {:#08x}".format(block.registers.regcontext.cax))

```

## Command line utility

This package comes with a small command line utility that prints all instructions from a trace:

```
usage: x64trace [trace file]
```

## About

Created by Florian Märkl

x64trace is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

x64trace is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with x64trace.  If not, see <http://www.gnu.org/licenses/>.

