import util.fs
import util.dependencies
import compile.release

class target:
	type: str
	path: str
	src: str
	def __init__(self, _type: str, _path: str, _src: str):
		self.type = _type
		self.path = _path
		self.src = _src

def getObjectPath(src: str):
	return src.replace("./src","./build").replace(".cxx",".o")

def buildTarget(trg: target, tcurrent: int, tmax: int):
	rebuild: bool = False
	depfile = trg.path+".deps.json"
	if util.fs.exists(depfile):
		dependencies = util.dependencies.load(depfile)
		lastBuild = dependencies["last build"]
		for file in dependencies["files"]:
			if util.fs.getModifiedTimestamp(file) > lastBuild:
				rebuild = True
				break
	else:
		rebuild = True
	if not rebuild:
		print(" \033[33m\U000025CE\033[0m",trg.path,"(",tcurrent,"/",tmax,")")
		return 0
	if trg.type == "c++ object":
		if compile.release.cpp(trg.src,trg.path,tcurrent,tmax) != 0:
			return 2
	return 0

def getTargetList() -> list[target]:
	targets: list[target] = list()
	for i in util.fs.getAllFilesOfExtension("./src","cxx"):
		targets.append(target("c++ object",getObjectPath(i),i))
	for i in util.fs.getAllFilesOfExtension("./src","cpp"):
		targets.append(target("c++ object",getObjectPath(i),i))
	for i in util.fs.getAllFilesOfExtension("./src","c"):
		targets.append(target("c object",getObjectPath(i),i))
	return targets

def getCleanList() -> list[str]:
	cleanFiles: list[str] = list()
	for target in getTargetList():
		cleanFiles.append(target.path)
		cleanFiles.append(target.path+".deps.json")
		cleanFiles.append(target.path+".d")
	return cleanFiles

def run() -> int:
	print(" \033[32m\U0001F6E0\033[0m running release build...")
	targets: list[target] = getTargetList()
	objects: list[str] = list()
	i: int = 1
	for trg in targets:
		objects.append(trg.path)
		if buildTarget(trg,i,targets.__len__()) != 0:
			return 2
		i+=1
	if compile.release.link(objects,"./HyperTextDisas") != 0:
		return 2
	print(" \033[32m\U0001F6E0\033[0m release build complete.")
	return 0