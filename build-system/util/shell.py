import os

def execvisual(cmd: str):
	ExitCode = os.system(cmd)
	if ExitCode == 0:
		print(" \033[32m\u25C6\033[0m",cmd)
	else:
		print(" \033[31m\u25C8\033[0m",cmd)
		
	