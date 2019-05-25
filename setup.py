from setuptools import setup

setup(
	name="x64trace",
	version="1.0.0",
	description="Library for loading x64dbg Trace Files",
	url="https://github.com/thestr4ng3r/x64trace-py",
	author="Florian Märkl",
	license="LGPLv3",
	clasifiers=[
		"License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
		"Operating System :: OS Independent",
		"Programming Language :: Python",
		"Programming Language :: Python :: 3 :: Only",
		"Programming Language :: Python :: 3.7",
	],
	keywords="x64dbg trace",
	packages=["x64trace"],
	entry_points={
		"console_scripts": [
			"x64trace = x64trace.__main__:main"
		]
	},
	python_requires=">=3.7",
	install_requires=[],
	extras_require={
		"disassembly": ["capstone"]
	}
)
