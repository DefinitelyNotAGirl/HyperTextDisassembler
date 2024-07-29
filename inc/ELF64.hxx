#pragma once

namespace elf64
{
	#pragma pack(1)
	constexpr uint32_t Magic = 0x464c457f;
	struct SectionHeader
	{
	    uint32_t Name;
	    uint32_t Type;
	    uint64_t Flags;
	    uint64_t VirtualAddress;
	    uint64_t OffsetInFile;
	    uint64_t SizeInFile;
	    uint32_t Link;
	    uint32_t Info;
	    uint64_t Alignment;
	    uint64_t EntrySize;
	};

	struct ProgramHeader
	{
    	uint32_t Type;
    	uint32_t Flags;
    	uint64_t OffsetInFile;
    	uint64_t VirtualAddress;
    	uint64_t PhysicalAddress;
    	uint64_t SizeInFile;
    	uint64_t SizeInMemory;
    	uint64_t Alignment;
	};

	struct Header
	{
    	uint32_t Magic;
    	uint8_t Class;
    	uint8_t Endianess;
    	uint8_t ElfVersion;
    	uint8_t SystemABI;
    	uint8_t AbiVersion;
    	uint8_t padding0[7];
    	uint16_t Type;
    	uint16_t Machine;
    	uint32_t Version;
    	uint64_t EntryPoint;
    	uint64_t ProgramHeaderTableOffset;
    	uint64_t SectionHeaderTableOffset;
    	uint32_t Flags;
    	uint16_t Length;
    	uint16_t ProgramHeaderSize;
    	uint16_t ProgramHeaderCount;
    	uint16_t SectionHeaderSize;
    	uint16_t SectionHeaderCount;
    	uint16_t SectionNameEntry;
	};

	namespace shf
	{
		constexpr uint64_t write 			= (1<< 0);
		constexpr uint64_t alloc 			= (1<< 1);
		constexpr uint64_t execinstr 		= (1<< 2);
		constexpr uint64_t merge			= (1<< 4);
		constexpr uint64_t strings			= (1<< 5);
		constexpr uint64_t info_link		= (1<< 6);
		constexpr uint64_t link_order		= (1<< 7);
		constexpr uint64_t os_nonconforming	= (1<< 8);
		constexpr uint64_t group			= (1<< 9);
		constexpr uint64_t tls				= (1<<10);
		constexpr uint64_t ordered 			= 0x4000000;
		constexpr uint64_t exclude 			= 0x8000000;
		constexpr uint64_t mask_os			= 0x0FF00000;
		constexpr uint64_t mask_proc		= 0xF0000000;
	}

	enum class RelocationType : uint32_t {
		R_X86_64_NONE			= 0,	//+ No relocation
		R_X86_64_64				= 1,	//+ Direct 64-bit
		R_X86_64_PC32			= 2,	//+ PC relative 32-bit signed
		R_X86_64_GOT32			= 3,	//+ 32-bit GOT entry
		R_X86_64_PLT32			= 4,	//+ 32-bit PLT address
		R_X86_64_COPY			= 5,	//+ Copy symbol at runtime
		R_X86_64_GLOB_DAT		= 6,	//+ Create GOT entry
		R_X86_64_JUMP_SLOT		= 7,	//+ Create PLT entry
		R_X86_64_RELATIVE		= 8,	//+ Adjust by program base
		R_X86_64_GOTPCREL		= 9,	//+ 32-bit signed PC relative offset to GOT
		R_X86_64_32				= 10,	//+ Direct 32-bit zero-extended
		R_X86_64_32S			= 11,	//+ Direct 32-bit sign-extended
		R_X86_64_16				= 12,	//+ Direct 16-bit zero-extended
		R_X86_64_PC16			= 13,	//+ 16-bit sign-extended PC relative
		R_X86_64_8				= 14,	//+ Direct 8-bit sign-extended
		R_X86_64_PC8			= 15,	//+ 8-bit sign-extended PC relative
		R_X86_64_DTPMOD64		= 16,	//+ ID of module containing symbol
		R_X86_64_DTPOFF64		= 17,	//+ Offset in module's TLS block
		R_X86_64_TPOFF64		= 18,	//+ Offset in initial TLS block
		R_X86_64_TLSGD			= 19,	//+ 32-bit signed PC relative offset to two GOT entries for GD symbol
		R_X86_64_TLSLD			= 20,	//+ 32-bit signed PC relative offset to two GOT entries for LD symbol
		R_X86_64_DTPOFF32		= 21,	//+ Offset in TLS block
		R_X86_64_GOTTPOFF		= 22,	//+ 32-bit signed PC relative offset to GOT entry for IE symbol
		R_X86_64_TPOFF32		= 23,	//+ Offset in initial TLS block
		R_X86_64_PC64			= 24,	//+ PC relative 64-bit
		R_X86_64_GOTOFF64		= 25,	//+ 64-bit offset to GOT
		R_X86_64_GOTPC32		= 26,	//+ 32-bit signed PC relative offset to GOT
		R_X86_64_GOT64			= 27,	//+ 64-bit GOT entry offset
		R_X86_64_GOTPCREL64		= 28,	//+ 64-bit PC relative offset to GOT entry
		R_X86_64_GOTPC64		= 29,	//+ 64-bit PC relative offset to GOT
		R_X86_64_GOTPLT64		= 30,	//+ Like GOT64, says PLT entry needed
		R_X86_64_PLTOFF64		= 31,	//+ 64-bit GOT relative offset to PLT entry
		R_X86_64_SIZE32			= 32,	//+ Size of symbol plus 32-bit addend
		R_X86_64_SIZE64			= 33,	//+ Size of symbol plus 64-bit addend
		R_X86_64_GOTPC32_TLSDESC= 34,	//+ GOT offset for TLS descriptor.
		R_X86_64_TLSDESC_CALL	= 35,	//+ Marker for call through TLS descriptor.
		R_X86_64_TLSDESC		= 36,	//+ TLS descriptor.
		R_X86_64_IRELATIVE		= 37,	//+ Adjust indirectly by program base
		R_X86_64_RELATIVE64		= 38,	//+ 64-bit adjust by program base
		R_X86_64_GOTPCRELX		= 41,	//+ Load from 32 bit signed pc relative offset to GOT
		R_X86_64_REX_GOTPCRELX	= 42,	//+ Load from 32 bit signed pc relative offset to GOT under REX
		R_X86_64_NUM			= 43	//+ Keep this the last entry
	};

	enum class SectionType : uint32_t
	{
		SHT_NULL				= 0,          // Section header table entry unused
		SHT_PROGBITS			= 1,          // Program data
		SHT_SYMTAB				= 2,          // Symbol table
		SHT_STRTAB				= 3,          // String table
		SHT_RELA				= 4,          // Relocation entries with addends
		SHT_HASH				= 5,          // Symbol hash table
		SHT_DYNAMIC				= 6,          // Dynamic linking information
		SHT_NOTE				= 7,          // Notes
		SHT_NOBITS				= 8,          // Program space with no data (bss)
		SHT_REL					= 9,          // Relocation entries, no addends
		SHT_SHLIB				= 10,         // Reserved
		SHT_DYNSYM				= 11,         // Dynamic linker symbol table
		SHT_INIT_ARRAY			= 14,         // Array of constructors
		SHT_FINI_ARRAY			= 15,         // Array of destructors
		SHT_PREINIT_ARRAY		= 16,         // Array of pre-constructors
		SHT_GROUP				= 17,         // Section group
		SHT_SYMTAB_SHNDX		= 18,         // Extended section indices
		SHT_NUM					= 19,         // Number of defined types.
		SHT_LOOS				= 0x60000000, // Start OS-specific.
		SHT_GNU_ATTRIBUTES		= 0x6ffffff5, // Object attributes.
		SHT_GNU_HASH			= 0x6ffffff6, // GNU-style hash table.
		SHT_GNU_LIBLIST			= 0x6ffffff7, // Prelink library list
		SHT_CHECKSUM			= 0x6ffffff8, // Checksum for DSO content.
		SHT_LOSUNW				= 0x6ffffffa, // Sun-specific low
		SHT_SUNW_move			= 0x6ffffffa,
		SHT_SUNW_COMDAT			= 0x6ffffffb,
		SHT_SUNW_syminfo		= 0x6ffffffc,
		SHT_GNU_verdef			= 0x6ffffffd, // Version definition section.
		SHT_GNU_verneed			= 0x6ffffffe, // Version needs section.
		SHT_GNU_versym			= 0x6fffffff, // Version symbol table.
		SHT_HISUNW				= 0x6fffffff, // Sun-specific high
		SHT_HIOS				= 0x6fffffff, // End OS-specific type
		SHT_LOPROC				= 0x70000000, // Start of processor-specific
		SHT_HIPROC				= 0x7fffffff, // End of processor-specific
		SHT_LOUSER				= 0x80000000, // Start of application-specific
		SHT_HIUSER				= 0x8fffffff  // End of application-specific
	};
	inline uint32_t to_uint32(SectionType type)
	{
		return static_cast<uint32_t>(type);
	}

	enum class ProgramHeaderType : uint32_t
	{
		PT_NULL				= 0,          // Program header table entry unused
		PT_LOAD				= 1,          // Loadable program segment
		PT_DYNAMIC			= 2,          // Dynamic linking information
		PT_INTERP			= 3,          // Program interpreter
		PT_NOTE				= 4,          // Auxiliary information
		PT_SHLIB			= 5,          // Reserved
		PT_PHDR				= 6,          // Entry for header table itself
		PT_TLS				= 7,          // Thread-local storage segment
		PT_NUM				= 8,          // Number of defined types
		PT_LOOS				= 0x60000000, // Start of OS-specific
		PT_GNU_EH_FRAME		= 0x6474e550, // GCC .eh_frame_hdr segment
		PT_GNU_STACK		= 0x6474e551, // Indicates stack executability
		PT_GNU_RELRO		= 0x6474e552, // Read-only after relocation
		PT_LOSUNW			= 0x6ffffffa, // Sun-specific low
		PT_SUNWBSS			= 0x6ffffffa, // Sun-specific bss
		PT_SUNWSTACK		= 0x6ffffffb, // Sun-specific stack
		PT_HISUNW			= 0x6fffffff, // Sun-specific high
		PT_HIOS				= 0x6fffffff, // End of OS-specific
		PT_LOPROC			= 0x70000000, // Start of processor-specific
		PT_HIPROC			= 0x7fffffff  // End of processor-specific
	};
	
	inline uint32_t to_uint32(ProgramHeaderType type)
	{
		return static_cast<uint32_t>(type);
	}

	struct RelocationEntry {
		uint64_t offset;
		uint64_t info;
		int64_t addend;
		RelocationEntry(uint64_t offset, uint32_t symbol, RelocationType rtype, int64_t addend)
			:offset(offset),info((((uint64_t)symbol)<<32) | ((uint32_t)rtype)),addend(addend){}
		u32 getSymbolIndex() {
			return this->info >> 32;
		}
		u32 getType() {
			return this->info;
		}
	};

	struct SymbolTableEntry {
		uint32_t name = 0;
		uint8_t info = 0;
		uint8_t other = 0;
		uint16_t SectionTableIndex = 0;
		uint64_t SymbolValue = 0;
		uint64_t SymbolSize = 0;
		SymbolTableEntry(){}
		SymbolTableEntry(SymbolTableEntry& e)
			:name(e.name),info(e.info),other(e.other),SectionTableIndex(e.SectionTableIndex),SymbolValue(e.SymbolValue),SymbolSize(e.SymbolSize){}
		SymbolTableEntry(uint32_t name,uint8_t info, uint8_t other, uint16_t SectionTableIndex, uint64_t SymbolValue, uint64_t SymbolSize)
			:name(name),info(info),other(other),SectionTableIndex(SectionTableIndex),SymbolValue(SymbolValue),SymbolSize(SymbolSize){}
	};

	enum class SectionTableIndex : uint16_t {
		/*
			. ELF64 spec
		*/
		UNDEF		= 0x0000,
		LORESERVE	= 0xff00,
		LOPROC		= 0xff00,
		HIPROC		= 0xff1f,
		LOOS		= 0xff20,
		HIOS		= 0xff3f,
		ABS			= 0xfff1,
		COMMON		= 0xfff2,
		XINDEX		= 0xffff,
		HIRESERVE	= 0xffff,
		/*
			. specific to this compiler
		*/
		SYMTAB	= 0x0001,
		TEXT 	= 0x0002,
		DATA 	= 0x0004,
		RODATA	= 0x0006,
	};
	inline uint16_t to_uint16(SectionTableIndex index)
	{
		return static_cast<uint16_t>(index);
	}
	#pragma pack()
}