#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

extern const char* masterStyleSheet;
std::string out = "<!DOCTYPE html><html><head><style>"+std::string(masterStyleSheet)+"</style></head>";

char* data;
uint64_t len;
uint64_t i = 0;

class hsl {
public:
	uint32_t hue;
	uint32_t saturation;
	uint32_t lightness;
	hsl(){}
	hsl(uint32_t hue, uint32_t saturation, uint32_t lightness)
		:hue(hue),saturation(saturation),lightness(lightness){}
	std::string css() {
		return "hsl("+std::to_string(this->hue)+","+std::to_string(this->saturation)+"%,"+std::to_string(this->lightness)+"%)";
	}
};

void process();
void proc_main()
{
	out+="<body>";
	process();
	out+="</body></html>";
}

void install_crash_handlers();
int main(int argc, char** argv)
{
	install_crash_handlers();
	if(argc != 2)
		std::cout << "argc != 2" << std::endl;

	std::string inputFile = argv[1];
	std::string outputFile = inputFile+".html";
	FILE* f = fopen(inputFile.c_str(),"r");
	fseek(f,0,SEEK_END);
	long flen = ftell(f);
	fseek(f,0,SEEK_SET);
	data = (char*)malloc(flen);
	fread((void*)data,flen,1,f);
	fclose(f);
	
	len = flen;
	proc_main();
	f = fopen(outputFile.c_str(),"w");
	fwrite(out.data(),out.length(),1,f);
	fclose(f);
}