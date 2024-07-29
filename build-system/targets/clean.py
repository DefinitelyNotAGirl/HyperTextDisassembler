import util.fs
import targets.debug
import targets.release
import os

def run() -> int:
	files: list[str] = list()
	files.extend(targets.debug.getCleanList())
	files.extend(targets.release.getCleanList())
	files = list(dict.fromkeys(files))
	for file in files:
		cmd = "rm "+file
		if util.fs.exists(file):
			if os.system(cmd) == 0:
				print(" \033[32m\u25CF\033[0m",cmd)
			else:
				print(" \033[31m\u25CB\033[0m",cmd)
		else:
			print(" \033[33m\u25CC\033[0m",cmd)
	print(" \033[32m\U0001F6E0\033[0m project cleaned.")	
	return 0