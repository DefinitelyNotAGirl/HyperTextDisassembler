import json
from datetime import datetime

def generateJSONFromMakeDep(md: str, out: str):
	deps = "{\n"
	deps += "\t\"last build\": "+str(datetime.now().timestamp())+",\n"
	deps += "\t\"files\":[\n"
	mdfile = open(md, 'r')
	mdlines = mdfile.readlines()
	i: int = 0
	for line in mdlines:
		frags = line.split(" ")
		for frag in frags:
			if(frag.endswith(":")):
				continue;
			if(frag == "\\\n"):
				continue;
			if(frag == ""):
				continue;
			if(i > 0):
				deps += ",\n"
			frag = frag.strip()
			deps += "\t\t\""+frag+"\""
			i+=1
	deps += "\n\t]\n}"
	outfile = open(out,'w')
	outfile.write(deps)

def load(file: str) -> any:
	decoder: json.JSONDecoder = json.JSONDecoder()
	return decoder.decode(open(file,'r').read())
