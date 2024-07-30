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
std::map<u64,std::map<u64,std::string>> FunctionStart;
std::map<u64,std::map<u64,std::string>> MiscSymbols;

std::string ToHex(u64 n) {
	std::stringstream stream;
	stream << std::hex << n;
	return stream.str();
}

std::string HexDisplay(u64 n) {
	return "<span class='HexDisplay'>0x"+ToHex(n)+"</span>";
}

std::string EncodedByteRange(Buffer& InstructionBuffer,u64 offset,u64 size,std::string Class) {
	std::string result;
	for(u64 i = 0;i<size;i++){
		std::string dstr = ToHex(InstructionBuffer.getU8(offset+i));
		if(dstr.length() == 1) {
			result+="<span class='byte encoded "+Class+"'>0"+dstr+"</span>";
		} else{
			result+="<span class='byte encoded "+Class+"'>"+dstr+"</span>";
		}
	}
	return result;
}

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

std::string InstructionComponent(std::string content,std::string Class) {
	return "<span class='InstructionComponent "+Class+"'>"+content+"</span>";
}

std::string EncodedBytes = "";
class DecodedModRM {
public:
	std::string reg;
	std::string rm;
	DecodedModRM(byte modrm,Buffer& InstructionBuffer,u64& offset,byte rex) {
		if(amd64::register_decode_base(amd64::decode::modrm::rm(modrm,rex)) != 0b100) {
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
		} else {
			throw InstructionBuffer.data;
		}
		this->reg = amd64::register_name(amd64::decode::modrm::reg(modrm,rex));
	}
};

void decodeInstruction(Section_Text& sec,Buffer& InstructionBuffer) {
	std::string Decoded;
	bool OperrandSizePrefix = false;
	bool AddressSizePrefix = false;
	bool LOCKSizePrefix = false;
	byte rex_prefix = 0x00;
	u64 offset = 0;
	while(offset <= 2) {
		if(InstructionBuffer.getU8(offset) == amd64::prefix::legacy::OperandSizeOverride) {
			Decoded += InstructionComponent("OSO","prefix");
			OperrandSizePrefix = true;
		} else if(InstructionBuffer.getU8(offset) == amd64::prefix::legacy::AddressSizeOverride) {
			Decoded += InstructionComponent("ASO","prefix");
			AddressSizePrefix = true;
		} else {
			break;
		}
		EncodedBytes += EncodedByteRange(InstructionBuffer,offset,1,"prefix");
		offset++;
	}
	if((InstructionBuffer.getU8(offset) & 0xF0) == 0x40) {
		rex_prefix = InstructionBuffer.getU8(offset);
		Decoded += InstructionComponent("REX","prefix");
		EncodedBytes += EncodedByteRange(InstructionBuffer,offset,1,"prefix");
		offset++;
	}
	byte opcode = InstructionBuffer.getU8(offset);
	EncodedBytes += EncodedByteRange(InstructionBuffer,offset,1,"opcode");
	//+
	//+	enter
	//+
	if(opcode == amd64::opcode::enter::rBP__imm16__imm8) {
		Decoded += InstructionComponent("enter","opcode");
		offset++;
		EncodedBytes += EncodedByteRange(InstructionBuffer,offset,2,"operrand1");
		Decoded += InstructionComponent(
			GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2),
			"operrand1"
		);
		offset+=2;
		EncodedBytes += EncodedByteRange(InstructionBuffer,offset,1,"operrand2");
		Decoded += InstructionComponent(
			GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,1),
			"operrand2"
		);
		offset+=1;
	}
	//+
	//+ mov reg/mem16/32/64, reg16/32/64
	//+
	else if(opcode == amd64::opcode::mov::rm16_32_64__r16_32_64) {
		Decoded += InstructionComponent("mov","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand2"
		);
	}
	//+
	//+ test reg/mem16/32/64, reg16/32/64
	//+
	else if(opcode == amd64::opcode::test::rm16_32_64__r16_32_64) {
		Decoded += InstructionComponent("test","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand2"
		);
	}
	//+
	//+ mov reg16/32/64, reg/mem16/32/64
	//+
	else if(opcode == amd64::opcode::mov::r16_32_64__rm16_32_64) {
		Decoded += InstructionComponent("mov","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand2"
		);
	}
	//+
	//+ add reg16/32/64, reg/mem16/32/64
	//+
	else if(opcode == amd64::opcode::add::r16_32_64__rm16_32_64) {
		Decoded += InstructionComponent("add","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand2"
		);
	}
	//+
	//+ add reg/mem8, reg8
	//+
	else if(opcode == amd64::opcode::add::rm8__r8) {
		Decoded += InstructionComponent("add","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand2"
		);
	}
	//+
	//+ xor reg16/32/64, reg/mem16/32/64
	//+
	else if(opcode == amd64::opcode::_xor::r16_32_64__rm16_32_64) {
		Decoded += InstructionComponent("xor","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand2"
		);
	}
	//+
	//+ cmp reg16/32/64, reg/mem16/32/64
	//+
	else if(opcode == amd64::opcode::cmp::r16_32_64__rm16_32_64) {
		Decoded += InstructionComponent("cmp","opcode");
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		Decoded += InstructionComponent(
			modrm.reg,
			"operrand1"
		);
		Decoded += InstructionComponent(
			modrm.rm,
			"operrand2"
		);
	}
	//+
	//+ mov r16/32/64 imm16/32/64
	//+
	else if((opcode & 0b11111000) == 0xB8) {
		Decoded += InstructionComponent("mov","opcode");
		Decoded += InstructionComponent(
			RegisterDisplay(amd64::register_name(amd64::decode::RegisterCode(opcode & 0b111,(rex_prefix & 0b1) == 1))),
			"operrand1"
		);
		offset++;
		if((rex_prefix & 0b1000) == 0b1000) {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,8,"operrand1");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,8),
				"operrand2"
			);
			offset+=8;
		} else if(OperrandSizePrefix) {
			//operrand2
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,2,"operrand2");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2),
				"operrand2"
			);
			offset+=2;
		} else {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,4,"operrand2");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,4),
				"operrand2"
			);
			offset+=4;
		}
	}
	//+
	//+ add RAX imm16/32/64
	//+
	else if(opcode == amd64::opcode::add::rAX__imm16_32) {
		Decoded += InstructionComponent("add","opcode");
		offset++;
		if((rex_prefix & 0b1000) == 0b1000) {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,8,"operrand1");
			Decoded += InstructionComponent(
				RegisterDisplay("rax"),
				"operrand1"
			);
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,8),
				"operrand2"
			);
			offset+=8;
		} else if(OperrandSizePrefix) {
			//operrand2
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,2,"operrand2");
			Decoded += InstructionComponent(
				RegisterDisplay("ax"),
				"operrand1"
			);
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2),
				"operrand2"
			);
			offset+=2;
		} else {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,4,"operrand2");
			Decoded += InstructionComponent(
				RegisterDisplay("eax"),
				"operrand1"
			);
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,4),
				"operrand2"
			);
			offset+=4;
		}
	}
	//+
	//+ call rel16/32
	//+
	else if(opcode == amd64::opcode::call::rel16_32) {
		Decoded += InstructionComponent("call","opcode");
		offset++;
		if(OperrandSizePrefix) {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,2,"operrand1");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2),
				"operrand1"
			);
			offset+=2;
		} else {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,4,"operrand1");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,4),
				"operrand1"
			);
			offset+=4;
		}
	}
	//+
	//+	secondary opcode map
	//+
	else if(opcode == 0x0F) {
		offset++;
		opcode = InstructionBuffer.getU8(offset);
		EncodedBytes += EncodedByteRange(InstructionBuffer,offset,1,"opcode");
		//+
		//+ jcc rel16/32
		//+
		if((opcode & 0xF0) == 0x80) {
			std::string mnemonic = "j"+amd64::decode::condition(opcode & 0x0F);
			Decoded += InstructionComponent(mnemonic,"opcode");
			offset++;
			if(OperrandSizePrefix) {
				EncodedBytes += EncodedByteRange(InstructionBuffer,offset,2,"operrand1");
				Decoded += InstructionComponent(
					GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2),
					"operrand1"
				);
				offset+=2;
			} else {
				EncodedBytes += EncodedByteRange(InstructionBuffer,offset,4,"operrand1");
				Decoded += InstructionComponent(
					GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,4),
					"operrand1"
				);
				offset+=4;
			}
		}
		//+
		//+ syscall
		//+
		else if(opcode == amd64::opcode::secondary::syscall) {
			Decoded += InstructionComponent("syscall","opcode");
			offset++;
		}
		else {
			throw InstructionBuffer.data;	
		}
	}
	//+
	//+ jcc rel8
	//+
	else if((opcode & 0xF0) == 0x70) {
		std::string mnemonic = "j"+amd64::decode::condition(opcode & 0x0F);
		Decoded += InstructionComponent(mnemonic,"opcode");
		offset++;
		EncodedBytes += EncodedByteRange(InstructionBuffer,offset,1,"operrand1");
		Decoded += InstructionComponent(
			GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,1),
			"operrand1"
		);
		offset+=1;
	}
	//+
	//+ jmp rel16/32
	//+
	else if(opcode == amd64::opcode::jmp::rel16_32) {
		Decoded += InstructionComponent("jmp","opcode");
		offset++;
		if(OperrandSizePrefix) {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,2,"operrand1");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,2),
				"operrand1"
			);
			offset+=2;
		} else {
			EncodedBytes += EncodedByteRange(InstructionBuffer,offset,4,"operrand1");
			Decoded += InstructionComponent(
				GetUnsignedImmediateRepresentation(sec,InstructionBuffer,offset,4),
				"operrand1"
			);
			offset+=4;
		}
	}
	//+
	//+ leave
	//+
	else if(opcode == amd64::opcode::leave::rBP) {
		Decoded += InstructionComponent("leave","opcode");
		offset++;
	}
	//+
	//+ retun (near)
	//+
	else if(opcode == amd64::opcode::ret_near::_) {
		Decoded += InstructionComponent("ret","opcode");
		offset++;
	}
	//+
	//+ 0xFF
	//+
	else if(opcode == 0xFF) {
		offset++;
		byte modrm_byte = InstructionBuffer.getU8(offset);
		u64 modrmoffset = offset;
		offset++;
		DecodedModRM modrm(modrm_byte,InstructionBuffer,offset,rex_prefix);
		EncodedBytes += EncodedByteRange(InstructionBuffer,modrmoffset,1,"modrm");
		if(amd64::decode::modrm::digit(modrm_byte)) {
			Decoded += InstructionComponent("push","opcode");
			Decoded += InstructionComponent(modrm.rm,"operrand1");
		}
	}
	else {
		throw InstructionBuffer.data;
	}
	InstructionBuffer.data += offset;
	out += "<td>"+EncodedBytes+"</td>";
	out += "<td>"+Decoded+"</td>";
}

void decodeSection(u64 sidx,Section_Text& s) {
	out += "<table><tr><td>Offset</td><td>Encoded</td><td>Decoded</td></tr>";
	try {
		Buffer InstructionBuffer;
		InstructionBuffer.data = s.data.data;
		InstructionBuffer.size = 16;
		while(InstructionBuffer.data < s.data.data+s.data.size) {
			try {
				std::string func = FunctionStart.at(sidx).at(InstructionBuffer.data-s.data.data);
				out += "<tr><td class='FunctionName'>"+func+"</td></tr>";
			} catch(std::out_of_range e) {
			}
			try {
				std::string sym = MiscSymbols.at(sidx).at(InstructionBuffer.data-s.data.data);
				out += "<tr><td class='SubSectionName'>"+sym+"</td></tr>";
			} catch(std::out_of_range e) {
			}
			out += "<tr><td>"+HexDisplay(InstructionBuffer.data-s.data.data)+"</td>";
			decodeInstruction(s,InstructionBuffer);
			out += "</tr>";
			EncodedBytes = "";
		}
	} catch(byte* address) {
		std::cout << "decoder failed at offset: " << (void*)(address-s.data.data) << std::endl;
		out += "<td>"+EncodedBytes+"</td><td class='failed'>decoder failed<td></tr>";
	}
	out += "</table>";
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
		FunctionStart.insert(std::pair<u64,std::map<u64,std::string>>(std::pair<u64,std::map<u64,std::string>>(i,std::map<u64,std::string>())));
		MiscSymbols.insert(std::pair<u64,std::map<u64,std::string>>(std::pair<u64,std::map<u64,std::string>>(i,std::map<u64,std::string>())));
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
							std::string(StringTables.at(hdr.Link)+Entry.name)
						));
						if((Entry.info & 0xF) == 0x2) {
							FunctionStart.at(Entry.SectionTableIndex).insert(
								std::pair<u64,std::string>(
									Entry.SymbolValue,
									std::string(StringTables.at(hdr.Link)+Entry.name)
								)
							);
						}else{
							MiscSymbols.at(Entry.SectionTableIndex).insert(
								std::pair<u64,std::string>(
									Entry.SymbolValue,
									std::string(StringTables.at(hdr.Link)+Entry.name)
								)
							);
						}
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
		decodeSection(i,TextSections.at(i));
	}
}
