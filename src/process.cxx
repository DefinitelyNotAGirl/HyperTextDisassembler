#include <cstdint>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t i64;
typedef int32_t i32;
typedef int16_t i16;
typedef int8_t i8;

#include <amd64.cgu.hxx>
#include <ELF64.hxx>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <iomanip>
#include <sstream>

extern char* data;
extern uint64_t len;
extern uint64_t i;
extern std::string out;
class Buffer {
public:
	byte* data;
	u64 size;
	u64 getU64(u64 offset) {
		return *((u64*)((byte*)this->data+offset));
	}
	u32 getU32(u64 offset) {
		return *((u32*)((byte*)this->data+offset));
	}
	u16 getU16(u64 offset) {
		return *((u16*)((byte*)this->data+offset));
	}
	u8 getU8(u64 offset) {
		return *((u8*)((byte*)this->data+offset));
	}
	i64 getI64(u64 offset) {
		return *((i64*)((byte*)this->data+offset));
	}
	i32 getI32(u64 offset) {
		return *((i32*)((byte*)this->data+offset));
	}
	i16 getI16(u64 offset) {
		return *((i16*)((byte*)this->data+offset));
	}
	i8 getI8(u64 offset) {
		return *((i8*)((byte*)this->data+offset));
	}
};

class Section_Text {
public:
	std::map<u64,std::string> Relocations;
	Buffer data;
};
std::map<u64,Section_Text> TextSections;
std::map<u64,char*> StringTables;
std::map<u64,std::map<u64,std::string>> SymbolRepresentationTables;
std::map<u64,std::string> SectionNames;
std::map<u64,std::string> FunctionStart;

std::string ToHex(u64 n) {
	std::stringstream stream;
	stream << std::hex << n;
	return stream.str();
}

std::string HexDisplay(u64 n) {
	return "<span class='HexDisplay'>0x"+ToHex(n)+"</span>";
}

std::string EncodedByteRange(Buffer& InstructionBuffer,u64 offset,u64 size) {
	std::string result;
	for(u64 i = 0;i<size;i++){
		std::string dstr = ToHex(InstructionBuffer.getU8(offset+i));
		if(dstr.length() == 1) {
			result+="<span class='byte'>0"+dstr+"</span>";
		} else{
			result+="<span class='byte'>"+dstr+"</span>";
		}
	}
	return result;
}

enum class InstructionComponentType {
	invalid = 0,
	prefix,
	opcode,
	operrand1,	
	operrand2,
	operrand3,
	immediate
};

class InstructionComponent {
public:
	InstructionComponentType Type = InstructionComponentType::invalid;
	std::string encoded;
	std::string decoded;

	InstructionComponent(){}
	InstructionComponent(InstructionComponentType Type,std::string encoded,std::string decoded) 
		:Type(Type),encoded(encoded),decoded(decoded){}
};

class InstructionDisplay {
public:
	std::vector<InstructionComponent> Components;
	std::string html() {
		std::string result = "<div class='instruction'>";
		std::string encoded = "";
		std::string decoded = "";
		for(InstructionComponent& c : this->Components) {
			std::string classes = "";
			switch(c.Type) {
				case(InstructionComponentType::opcode):
					classes="opcode";
					break;
				case(InstructionComponentType::prefix):
					classes="prefix";
					break;
				case(InstructionComponentType::operrand1):
					classes="operrand1";
					break;
				case(InstructionComponentType::operrand2):
					classes="operrand2";
					break;
				case(InstructionComponentType::operrand3):
					classes="operrand3";
					break;
			}
			encoded += "<span class='"+classes+"'>"+c.encoded+"</span>";
			decoded += "<span class='"+classes+"'>"+c.decoded+"</span>";
		}
		result+="<div class='encoded'>"+encoded+"</div>";
		result+="<div class='decoded'>"+decoded+"</div>";
		result+="</div>";
		std::cout << "instruction display: " << result << std::endl;
		return result;
	}
};

std::string GetUnsignedImmediateRepresentation(Section_Text& sec,Buffer& InstructionBuffer,u64 offset,u64 size) {
	try {
		return sec.Relocations.at((InstructionBuffer.data+offset)-sec.data.data);
	} catch(std::out_of_range e) {
		switch(size) {
			case(8): return HexDisplay(InstructionBuffer.getU64(offset));
			case(4): return HexDisplay(InstructionBuffer.getU32(offset));
			case(2): return HexDisplay(InstructionBuffer.getU16(offset));
			case(1): return HexDisplay(InstructionBuffer.getU8(offset));
		}
	}
	throw InstructionBuffer.data;
}

std::string RegisterDisplay(std::string name) {
	return "<span class='RegisterName'>"+name+"</span>";
}

class DecodedModRM {
public:
	std::string reg;
	std::string rm;
	DecodedModRM(byte modrm,Buffer& InstructionBuffer,u64& offset,byte rex) {
		if(amd64::decode::modrm::mod(modrm) == amd64::AddressingMode::RegisterDirect) {
			this->rm = RegisterDisplay(amd64::register_name(amd64::decode::modrm::rm(modrm,rex)));
		}
		else if(amd64::decode::modrm::mod(modrm) == amd64::AddressingMode::RegisterIndirect) {
			this->rm = "["+RegisterDisplay(amd64::register_name(amd64::decode::modrm::rm(modrm,rex)))+"]";
		}
		else if(amd64::decode::modrm::mod(modrm) == amd64::AddressingMode::RegisterIndirect_disp8) {
			this->rm = "["+RegisterDisplay(amd64::register_name(amd64::decode::modrm::rm(modrm,rex)))+"+"+HexDisplay(InstructionBuffer.getU8(offset))+"]";
			offset+=1;
		}
		else if(amd64::decode::modrm::mod(modrm) == amd64::AddressingMode::RegisterIndirect_disp32) {
			this->rm = "["+RegisterDisplay(amd64::register_name(amd64::decode::modrm::rm(modrm,rex)))+"+"+HexDisplay(InstructionBuffer.getU8(offset))+"]";
			offset+=4;
		}
	}
};

void decodeInstruction(Section_Text& sec,Buffer& InstructionBuffer) {
	InstructionDisplay Display;
	bool OperrandSizePrefix = false;
	bool AddressSizePrefix = false;
	bool LOCKSizePrefix = false;
	byte rex_prefix = 0x00;
	u16 offset = 0;
	while(offset <= 2) {
		if(InstructionBuffer.getU8(offset) == amd64::prefix::legacy::OperandSizeOverride) {
			Display.Components.push_back(InstructionComponent(
				InstructionComponentType::prefix,
				HexDisplay(amd64::prefix::legacy::OperandSizeOverride),
				"OSO"
			));
			OperrandSizePrefix = true;
		} else if(InstructionBuffer.getU8(offset) == amd64::prefix::legacy::AddressSizeOverride) {
			Display.Components.push_back(InstructionComponent(
				InstructionComponentType::prefix,
				HexDisplay(amd64::prefix::legacy::AddressSizeOverride),
				"ASO"
			));
			AddressSizePrefix = true;
		} else {
			break;
		}
		offset++;
	}
	if((InstructionBuffer.getU8(offset) & 0xF0) == 0x40) {
		rex_prefix = InstructionBuffer.getU8(offset);
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::prefix,
			HexDisplay(rex_prefix),
			"REX"
		));
		offset++;
	}
	byte opcode = InstructionBuffer.getU8(offset);
	//.
	//.	enter
	//.
	if(opcode == amd64::opcode::enter::rBP__imm16__imm8) {
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::opcode,
			EncodedByteRange(InstructionBuffer,offset,1),
			"enter"
		));
		offset++;
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::operrand1,
			EncodedByteRange(InstructionBuffer,offset,2),
			GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2)
		));
		offset+=2;
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::operrand2,
			EncodedByteRange(InstructionBuffer,offset,1),
			GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,1)
		));
		offset+=1;
	}
	//+
	//+ MOV reg/mem64, reg64
	//+
	else if(opcode == amd64::opcode::mov::rm16_32_64__r16_32_64) {
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::opcode,
			EncodedByteRange(InstructionBuffer,offset,1),
			"mov"
		));
		offset++;
		byte modrm = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::operrand2,
			"",
			amd64::register_name(amd64::decode::modrm::reg(modrm,rex_prefix))
		));
	}
	//+
	//+ call rel16/32
	//+
	else if(opcode == amd64::opcode::call::rel16_32) {
		Display.Components.push_back(InstructionComponent(
			InstructionComponentType::opcode,
			EncodedByteRange(InstructionBuffer,offset,1),
			"call"
		));
		offset++;
		if(OperrandSizePrefix) {
			Display.Components.push_back(InstructionComponent(
				InstructionComponentType::operrand1,
				EncodedByteRange(InstructionBuffer,offset,2),
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2)
			));
			offset+=2;
		} else {
			Display.Components.push_back(InstructionComponent(
				InstructionComponentType::operrand1,
				EncodedByteRange(InstructionBuffer,offset,4),
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,4)
			));
			offset+=4;
		}
	}
	else {
		throw InstructionBuffer.data;
	}
	InstructionBuffer.data += offset;
	out += Display.html();
}

void decodeSection(Section_Text& s) {
	try {
		Buffer InstructionBuffer;
		InstructionBuffer.data = s.data.data;
		InstructionBuffer.size = 16;
		while(InstructionBuffer.data < s.data.data+s.data.size) {
			decodeInstruction(s,InstructionBuffer);
		}
	} catch(byte* address) {
		std::cout << "decoder failed at offset: " << (void*)(address-s.data.data) << std::endl;
	}
}

void process()
{
	std::vector<u64> tsecs;
	elf64::Header* Header = (elf64::Header*)(data+0);
	if(Header->Magic != elf64::Magic) {
		std::cerr << "ERROR: invalid ELF64 magic" << std::endl;
	}
	elf64::SectionHeader* SectionHeaders = (elf64::SectionHeader*)(data+Header->SectionHeaderSize);
	for(u64 i = 0;i<Header->SectionHeaderCount;i++) {
		if(SectionHeaders[i].Type == (u32)elf64::SectionType::SHT_STRTAB) {
			StringTables.insert(std::pair<u64,char*>(i,(char*)(SectionHeaders[i].OffsetInFile+data)));
		}
	}
	for(u64 i = 0;i<Header->SectionHeaderCount;i++) {
		SectionNames.insert(std::pair<u64,std::string>(i,std::string(StringTables.at(Header->SectionNameEntry)+SectionHeaders[i].Name)));
		if((SectionHeaders[i].Type == (u32)elf64::SectionType::SHT_PROGBITS) && (SectionHeaders[i].Flags == 0b110)) {
			Section_Text sec;
			sec.data.data = (byte*)(SectionHeaders[i].OffsetInFile+data);
			sec.data.size = SectionHeaders[i].SizeInFile;
			tsecs.push_back(i);
			TextSections.insert(std::pair<u64,Section_Text>(i,sec));
		}
	}
	for(u64 i = 0;i<Header->SectionHeaderCount;i++) {
		elf64::SectionHeader& hdr = SectionHeaders[i];
		if(hdr.Type == (u32)elf64::SectionType::SHT_SYMTAB) {
			SymbolRepresentationTables.insert(std::pair<u64,std::map<u64,std::string>>(i,std::map<u64,std::string>()));
			u64 EntryCount = hdr.SizeInFile/sizeof(elf64::SymbolTableEntry);
			elf64::SymbolTableEntry* Entries = (elf64::SymbolTableEntry*)(hdr.OffsetInFile+data);
			for(u64 e = 0;e<EntryCount;e++) {
				elf64::SymbolTableEntry& Entry = Entries[e];
				switch((u64)Entry.SectionTableIndex) {
					case((u64)elf64::SectionTableIndex::UNDEF): {
						SymbolRepresentationTables.at(i).insert(std::pair<u64,std::string>(e,
							std::string(StringTables.at(hdr.Link)+Entry.name)
						));
					}
					case((u64)elf64::SectionTableIndex::ABS): {
						SymbolRepresentationTables.at(i).insert(std::pair<u64,std::string>(e,
							std::to_string(Entry.SymbolValue)
						));
					}
					default: {
						SymbolRepresentationTables.at(i).insert(std::pair<u64,std::string>(e,
							SectionNames.at(Entry.SectionTableIndex)+"+"+std::to_string(Entry.SymbolValue)
						));
					}
				}
			}
		}
	}
	for(u64 i = 0;i<Header->SectionHeaderCount;i++) {
		elf64::SectionHeader& hdr = SectionHeaders[i];
		if(hdr.Type == (u32)elf64::SectionType::SHT_RELA) {
			try {
				Section_Text& sec = TextSections.at(hdr.Info);
				u64 EntryCount = hdr.SizeInFile/sizeof(elf64::RelocationEntry);
				elf64::RelocationEntry* Entries = (elf64::RelocationEntry*)(hdr.OffsetInFile+data);
				for(u64 e = 0;e<EntryCount;e++) {
					elf64::RelocationEntry& Entry = Entries[e];
					//std::cout << "Relocation: " << SectionNames.at(hdr.Info) << "+" << Entry.offset << ": " << "<"+SymbolRepresentationTables.at(hdr.Link).at(Entry.getSymbolIndex())+"+"+std::to_string(Entry.addend)+">" << std::endl;
					sec.Relocations.insert(std::pair<u64,std::string>(
						Entry.offset,
						Entry.addend == 0 ?
							SymbolRepresentationTables.at(hdr.Link).at(Entry.getSymbolIndex())
							: SymbolRepresentationTables.at(hdr.Link).at(Entry.getSymbolIndex())+"+"+std::to_string(Entry.addend)
					));
				}
			} catch(std::out_of_range e) {
			}
		}
	}
	for(u64 i : tsecs) {
		decodeSection(TextSections.at(i));
	}
}
