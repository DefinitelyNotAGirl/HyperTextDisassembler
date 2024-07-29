import glob
import os

def getAllFilesOfExtension(dir: str,ext: str):
	return glob.glob(dir+"/**/*"+ext,recursive=True)

def getModifiedTimestamp(path: str) -> float:
	return os.path.getmtime(path)

def exists(path: str) -> bool:
	return os.path.exists(path)

def readAll(path: str) -> str:
	return open(path,'r').read()
