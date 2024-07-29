import os
import options

import util.dependencies
import util.fs

import subprocess

def cpp(src: str, out: str, tcurrent: int, tmax: int) -> int:
	ExitCode: int = 0
	#+
	#+ compile
	#+
	print(" \033[34m\u25C9\033[0m",src,"(",tcurrent,"/",tmax,")")
	if options.compiler_cxx == "g++":
		ExitCode = os.system(options.compiler_cxx+" -o "+out+" "+src+" -MD -MF "+out+".d "+options.args_cxx+" &> ./build/.stdout")
	elif options.compiler_cxx == "clang++":
		ExitCode = os.system(options.compiler_cxx+" -o "+out+" "+src+" -MD -MF "+out+".d "+options.args_cxx+" &> ./build/.stdout")
	print("\033[1F",end='')
	if ExitCode != 0:
		print(" \033[31m\u25CB\033[0m",src,"(",tcurrent,"/",tmax,")")
		print(util.fs.readAll("./build/.stdout"),end='')
		return ExitCode
	#+
	#+ generate dep file
	#+
	util.dependencies.generateJSONFromMakeDep(out+".d",out+".deps.json")
	print(" \033[32m\u25CF\033[0m",src,"(",tcurrent,"/",tmax,")")
	print(util.fs.readAll("./build/.stdout"),end='')
	return ExitCode

def link(objects: list[str],out: str) -> int:
	ExitCode: int = 0
	cmd = options.linker
	for object in objects:
		cmd += " "+object
	cmd += " "+options.args_linker
	cmd += " -o "+out+" &> ./build/.stdout"
	#+
	#+ link
	#+
	ExitCode = os.system(cmd)
	if ExitCode != 0:
		print(" \033[31m\u25CB\033[0m",out)
		print(util.fs.readAll("./build/.stdout"),end='')
		return ExitCode
	print(" \033[32m\u25CF\033[0m",out)
	print(util.fs.readAll("./build/.stdout"),end='')
	return ExitCode
