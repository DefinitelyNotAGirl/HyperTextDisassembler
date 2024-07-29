#pragma once
#include <cstdint>
#include <string>
typedef uint8_t byte;

namespace amd64
{
	inline constexpr uint64_t register_encode_cpl( uint8_t pl ){return ((uint64_t)pl)<<11;}
	inline constexpr uint64_t register_encode_msr(uint32_t ecx){return (((uint64_t)ecx)<<32) | (1<<4);}
	inline constexpr uint64_t register_encode_float8 (){return (1<<5);}
	inline constexpr uint64_t register_encode_float16(){return (1<<8);}
	inline constexpr uint64_t register_encode_float32(){return (1<<9);}
	inline constexpr uint64_t register_encode_highbyte(){return (1<<10);}
	inline constexpr uint64_t register_encode_rex(){return (1<<3);}
	inline constexpr uint64_t register_encode_base(uint8_t encoding){return encoding & 0b111;}
	inline constexpr uint64_t register_encode_control(){return (1<<6);}
	inline constexpr uint64_t register_encode_special(){return (1<<7);}
	/**
	* @brief
	*	bits 0-2: register encoding
	*	bit 3: REX register extension
	*	bit 4: indicates that this is a model specific register, in which case the ECX value is held in bits 32-63
	*	bit 5: indicates that this is an x86 mmx register
	*	bit 6: indicates that this is an x86-64 control register
	*	bit 7: misc special register
	*	bit 8: indicates that this is an x86 xmm register
	*	bit 9: indicates that this is an x86 ymm register
	*	bit 10: indicates that this is an x86 high byte register
	*	bit 11-12: max cpl, software with privelege higher than this value can't access this register
	*/
	enum class Register : uint64_t {
		invalid = 0xFFFFFFFFFFFFFFFF,
		/* original integer registers */
		rax = register_encode_cpl(3) | register_encode_base(0x00),
		rcx = register_encode_cpl(3) | register_encode_base(0x01),
		rdx = register_encode_cpl(3) | register_encode_base(0x02),
		rbx = register_encode_cpl(3) | register_encode_base(0x03),
		rsp = register_encode_cpl(3) | register_encode_base(0x04),
		rbp = register_encode_cpl(3) | register_encode_base(0x05),
		rsi = register_encode_cpl(3) | register_encode_base(0x06),
		rdi = register_encode_cpl(3) | register_encode_base(0x07),
		/* high byte registers */
		ah = register_encode_cpl(3) | register_encode_highbyte() | register_encode_base(0x04),
		ch = register_encode_cpl(3) | register_encode_highbyte() | register_encode_base(0x05),
		dh = register_encode_cpl(3) | register_encode_highbyte() | register_encode_base(0x06),
		bh = register_encode_cpl(3) | register_encode_highbyte() | register_encode_base(0x07),
		/* r8-r15 */
		r8  = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x00),
		r9  = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x01),
		r10 = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x02),
		r11 = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x03),
		r12 = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x04),
		r13 = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x05),
		r14 = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x06),
		r15 = register_encode_cpl(3) | register_encode_rex() | register_encode_base(0x07),
		/* mmx */
		mmx0 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x00),
		mmx1 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x01),
		mmx2 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x02),
		mmx3 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x03),
		mmx4 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x04),
		mmx5 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x05),
		mmx6 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x06),
		mmx7 = register_encode_cpl(3) | register_encode_float8() | register_encode_base(0x07),
		/* xmm */
		xmm0 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x00),
		xmm1 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x01),
		xmm2 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x02),
		xmm3 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x03),
		xmm4 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x04),
		xmm5 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x05),
		xmm6 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x06),
		xmm7 = register_encode_cpl(3) | register_encode_float16() | register_encode_base(0x07),
		/* ymm */
		ymm0 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x00),
		ymm1 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x01),
		ymm2 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x02),
		ymm3 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x03),
		ymm4 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x04),
		ymm5 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x05),
		ymm6 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x06),
		ymm7 = register_encode_cpl(3) | register_encode_float32() | register_encode_base(0x07),
		/* cr0-15 */
		//TODO: correct values on these registers, base is bogus to avoid compiler errors
		cr0 = register_encode_cpl(0) | register_encode_control() |register_encode_base(0),
		cr2 = register_encode_cpl(0) | register_encode_control() |register_encode_base(1),
		cr3 = register_encode_cpl(0) | register_encode_control() |register_encode_base(2),
		cr4 = register_encode_cpl(0) | register_encode_control() |register_encode_base(3),
		cr8 = register_encode_cpl(0) | register_encode_rex() | register_encode_control() | register_encode_base(4),
		/* descriptor table registers */
		//TODO: correct values on these registers, base is bogus to avoid compiler errors
		gdtr = register_encode_cpl(3) | register_encode_special() | register_encode_base(0),
		idtr = register_encode_cpl(3) | register_encode_special() | register_encode_base(1),
		ldtr = register_encode_cpl(3) | register_encode_special() | register_encode_base(2),
		/* model specific registers */
		efer 			= register_encode_cpl(0) | register_encode_msr(0xC0000080),
		star 			= register_encode_cpl(0) | register_encode_msr(0xC0000081),
		lstar 			= register_encode_cpl(0) | register_encode_msr(0xC0000082),
		cstar 			= register_encode_cpl(0) | register_encode_msr(0xC0000083),
		sfmask 			= register_encode_cpl(0) | register_encode_msr(0xC0000084),
		fs_base 		= register_encode_cpl(0) | register_encode_msr(0xC0000100),
		gs_base 		= register_encode_cpl(0) | register_encode_msr(0xC0000101),
		kernel_gs_base 	= register_encode_cpl(0) | register_encode_msr(0xC0000102),
		tsc_aux 		= register_encode_cpl(0) | register_encode_msr(0xC0000103),
		syscfg 			= register_encode_cpl(0) | register_encode_msr(0xC0010010),
		iorr_base0 		= register_encode_cpl(0) | register_encode_msr(0xC0010016),
		iorrmask0 		= register_encode_cpl(0) | register_encode_msr(0xC0010017),
		iorr_base1 		= register_encode_cpl(0) | register_encode_msr(0xC0010018),
		iorrmask1 		= register_encode_cpl(0) | register_encode_msr(0xC0010019),
		ls_cfg 			= register_encode_cpl(0) | register_encode_msr(0xC0011020),
		ic_cfg 			= register_encode_cpl(0) | register_encode_msr(0xC0011021),
		dc_cfg 			= register_encode_cpl(0) | register_encode_msr(0xC0011022),
		bu_cfg 			= register_encode_cpl(0) | register_encode_msr(0xC0011023),
		mc0_ctl 		= register_encode_cpl(0) | register_encode_msr(0xC0010040),
		mc0_status 		= register_encode_cpl(0) | register_encode_msr(0xC0010041),
		mc0_addr 		= register_encode_cpl(0) | register_encode_msr(0xC0010042),
		mc0_misc 		= register_encode_cpl(0) | register_encode_msr(0xC0010043),
		perf_ctl0 		= register_encode_cpl(0) | register_encode_msr(0xC0010000),
		perf_ctr0 		= register_encode_cpl(0) | register_encode_msr(0xC0010004),
		perf_ctl1 		= register_encode_cpl(0) | register_encode_msr(0xC0010001),
		perf_ctr1 		= register_encode_cpl(0) | register_encode_msr(0xC0010005),
		top_mem 		= register_encode_cpl(0) | register_encode_msr(0xC001001A),
		top_mem2 		= register_encode_cpl(0) | register_encode_msr(0xC001001D),
		vm_cr 			= register_encode_cpl(0) | register_encode_msr(0xC0010114),
		vm_hsave_pa 	= register_encode_cpl(0) | register_encode_msr(0xC0010117)
	};
	inline constexpr uint64_t register_decode_cpl	(Register reg){return (((uint64_t)reg)&(0b11<<11))>>11;};
	inline constexpr uint64_t register_decode_base	(Register reg){return (((uint64_t)reg)&(0b111<<0))>>0;};
	inline constexpr uint64_t register_decode_rex	(Register reg){return (((uint64_t)reg)&(1<<3))>>3;};

	const char* register_name(Register reg) {
		switch (reg) {
			case Register::invalid: return "invalid";
			case Register::rax: return "rax";
			case Register::rcx: return "rcx";
			case Register::rdx: return "rdx";
			case Register::rbx: return "rbx";
			case Register::rsp: return "rsp";
			case Register::rbp: return "rbp";
			case Register::rsi: return "rsi";
			case Register::rdi: return "rdi";
			case Register::ah: return "ah";
			case Register::ch: return "ch";
			case Register::dh: return "dh";
			case Register::bh: return "bh";
			case Register::r8: return "r8";
			case Register::r9: return "r9";
			case Register::r10: return "r10";
			case Register::r11: return "r11";
			case Register::r12: return "r12";
			case Register::r13: return "r13";
			case Register::r14: return "r14";
			case Register::r15: return "r15";
			case Register::mmx0: return "mmx0";
			case Register::mmx1: return "mmx1";
			case Register::mmx2: return "mmx2";
			case Register::mmx3: return "mmx3";
			case Register::mmx4: return "mmx4";
			case Register::mmx5: return "mmx5";
			case Register::mmx6: return "mmx6";
			case Register::mmx7: return "mmx7";
			case Register::xmm0: return "xmm0";
			case Register::xmm1: return "xmm1";
			case Register::xmm2: return "xmm2";
			case Register::xmm3: return "xmm3";
			case Register::xmm4: return "xmm4";
			case Register::xmm5: return "xmm5";
			case Register::xmm6: return "xmm6";
			case Register::xmm7: return "xmm7";
			case Register::ymm0: return "ymm0";
			case Register::ymm1: return "ymm1";
			case Register::ymm2: return "ymm2";
			case Register::ymm3: return "ymm3";
			case Register::ymm4: return "ymm4";
			case Register::ymm5: return "ymm5";
			case Register::ymm6: return "ymm6";
			case Register::ymm7: return "ymm7";
			case Register::cr0: return "cr0";
			case Register::cr2: return "cr2";
			case Register::cr3: return "cr3";
			case Register::cr4: return "cr4";
			case Register::cr8: return "cr8";
			case Register::gdtr: return "gdtr";
			case Register::idtr: return "idtr";
			case Register::ldtr: return "ldtr";
			case Register::efer: return "efer";
			case Register::star: return "star";
			case Register::lstar: return "lstar";
			case Register::cstar: return "cstar";
			case Register::sfmask: return "sfmask";
			case Register::fs_base: return "fs_base";
			case Register::gs_base: return "gs_base";
			case Register::kernel_gs_base: return "kernel_gs_base";
			case Register::tsc_aux: return "tsc_aux";
			case Register::syscfg: return "syscfg";
			case Register::iorr_base0: return "iorr_base0";
			case Register::iorrmask0: return "iorrmask0";
			case Register::iorr_base1: return "iorr_base1";
			case Register::iorrmask1: return "iorrmask1";
			case Register::ls_cfg: return "ls_cfg";
			case Register::ic_cfg: return "ic_cfg";
			case Register::dc_cfg: return "dc_cfg";
			case Register::bu_cfg: return "bu_cfg";
			case Register::mc0_ctl: return "mc0_ctl";
			case Register::mc0_status: return "mc0_status";
			case Register::mc0_addr: return "mc0_addr";
			case Register::mc0_misc: return "mc0_misc";
			case Register::perf_ctl0: return "perf_ctl0";
			case Register::perf_ctr0: return "perf_ctr0";
			case Register::perf_ctl1: return "perf_ctl1";
			case Register::perf_ctr1: return "perf_ctr1";
			case Register::top_mem: return "top_mem";
			case Register::top_mem2: return "top_mem2";
			case Register::vm_cr: return "vm_cr";
			case Register::vm_hsave_pa: return "vm_hsave_pa";
			default: return "invalid amd64 register";
		}
	}

	Register string_to_register(const std::string& reg_str) {
		if (reg_str == "invalid") return Register::invalid;
		if (reg_str == "rax") return Register::rax;
		if (reg_str == "rcx") return Register::rcx;
		if (reg_str == "rdx") return Register::rdx;
		if (reg_str == "rbx") return Register::rbx;
		if (reg_str == "rsp") return Register::rsp;
		if (reg_str == "rbp") return Register::rbp;
		if (reg_str == "rsi") return Register::rsi;
		if (reg_str == "rdi") return Register::rdi;
		if (reg_str == "ah") return Register::ah;
		if (reg_str == "ch") return Register::ch;
		if (reg_str == "dh") return Register::dh;
		if (reg_str == "bh") return Register::bh;
		if (reg_str == "r8") return Register::r8;
		if (reg_str == "r9") return Register::r9;
		if (reg_str == "r10") return Register::r10;
		if (reg_str == "r11") return Register::r11;
		if (reg_str == "r12") return Register::r12;
		if (reg_str == "r13") return Register::r13;
		if (reg_str == "r14") return Register::r14;
		if (reg_str == "r15") return Register::r15;
		if (reg_str == "mmx0") return Register::mmx0;
		if (reg_str == "mmx1") return Register::mmx1;
		if (reg_str == "mmx2") return Register::mmx2;
		if (reg_str == "mmx3") return Register::mmx3;
		if (reg_str == "mmx4") return Register::mmx4;
		if (reg_str == "mmx5") return Register::mmx5;
		if (reg_str == "mmx6") return Register::mmx6;
		if (reg_str == "mmx7") return Register::mmx7;
		if (reg_str == "xmm0") return Register::xmm0;
		if (reg_str == "xmm1") return Register::xmm1;
		if (reg_str == "xmm2") return Register::xmm2;
		if (reg_str == "xmm3") return Register::xmm3;
		if (reg_str == "xmm4") return Register::xmm4;
		if (reg_str == "xmm5") return Register::xmm5;
		if (reg_str == "xmm6") return Register::xmm6;
		if (reg_str == "xmm7") return Register::xmm7;
		if (reg_str == "ymm0") return Register::ymm0;
		if (reg_str == "ymm1") return Register::ymm1;
		if (reg_str == "ymm2") return Register::ymm2;
		if (reg_str == "ymm3") return Register::ymm3;
		if (reg_str == "ymm4") return Register::ymm4;
		if (reg_str == "ymm5") return Register::ymm5;
		if (reg_str == "ymm6") return Register::ymm6;
		if (reg_str == "ymm7") return Register::ymm7;
		if (reg_str == "cr0") return Register::cr0;
		if (reg_str == "cr2") return Register::cr2;
		if (reg_str == "cr3") return Register::cr3;
		if (reg_str == "cr4") return Register::cr4;
		if (reg_str == "cr8") return Register::cr8;
		if (reg_str == "gdtr") return Register::gdtr;
		if (reg_str == "idtr") return Register::idtr;
		if (reg_str == "ldtr") return Register::ldtr;
		if (reg_str == "efer") return Register::efer;
		if (reg_str == "star") return Register::star;
		if (reg_str == "lstar") return Register::lstar;
		if (reg_str == "cstar") return Register::cstar;
		if (reg_str == "sfmask") return Register::sfmask;
		if (reg_str == "fs_base") return Register::fs_base;
		if (reg_str == "gs_base") return Register::gs_base;
		if (reg_str == "kernel_gs_base") return Register::kernel_gs_base;
		if (reg_str == "tsc_aux") return Register::tsc_aux;
		if (reg_str == "syscfg") return Register::syscfg;
		if (reg_str == "iorr_base0") return Register::iorr_base0;
		if (reg_str == "iorrmask0") return Register::iorrmask0;
		if (reg_str == "iorr_base1") return Register::iorr_base1;
		if (reg_str == "iorrmask1") return Register::iorrmask1;
		if (reg_str == "ls_cfg") return Register::ls_cfg;
		if (reg_str == "ic_cfg") return Register::ic_cfg;
		if (reg_str == "dc_cfg") return Register::dc_cfg;
		if (reg_str == "bu_cfg") return Register::bu_cfg;
		if (reg_str == "mc0_ctl") return Register::mc0_ctl;
		if (reg_str == "mc0_status") return Register::mc0_status;
		if (reg_str == "mc0_addr") return Register::mc0_addr;
		if (reg_str == "mc0_misc") return Register::mc0_misc;
		if (reg_str == "perf_ctl0") return Register::perf_ctl0;
		if (reg_str == "perf_ctr0") return Register::perf_ctr0;
		if (reg_str == "perf_ctl1") return Register::perf_ctl1;
		if (reg_str == "perf_ctr1") return Register::perf_ctr1;
		if (reg_str == "top_mem") return Register::top_mem;
		if (reg_str == "top_mem2") return Register::top_mem2;
		if (reg_str == "vm_cr") return Register::vm_cr;
		if (reg_str == "vm_hsave_pa") return Register::vm_hsave_pa;
		return Register::invalid;
	}

	constexpr uint64_t operator<<(Register r,uint64_t i){return ((uint64_t)r)<<i;}
	constexpr uint64_t operator&(Register r,uint64_t i){return ((uint64_t)r)&i;}

	enum class StorageMode {
		IndirectImmediate,
		IndirectRegister,
		DirectImmediate,
		DirectRegister,
		SII,
		SIB
	};
	/**
	* @brief each value in this enum really only has 2 bits, the upper 6 are to be ignored
	*/
	enum class AddressingMode : uint8_t {
		RegisterDirect 			= 0b11,
		RegisterIndirect  		= 0b00,
		RegisterIndirect_disp8  = 0b01,
		RegisterIndirect_disp32 = 0b10
	};
	constexpr uint8_t operator<<(AddressingMode am,uint8_t i){return ((uint8_t)am)<<i;}

	/**
	* @brief generates a modRM byte that only specifies one reg/mem operrand
	* 
	* @param digit specified in the amd64 specification
	* @param rm reg/mem opperand
	* @return amd64 modRM byte ready for execution
	*/
	inline byte modRM(uint8_t digit,AddressingMode mod,Register rm)
	{
		return (digit<<3) | (mod<<6) | (rm<<0);	
	}
	/**
	 * @brief
	 * 
	 * @param reg reg operrand
	 * @param rm reg/mem opperand
	 * @return amd64 modRM byte ready for execution
	 */
	inline byte modRM(Register reg,AddressingMode mod,Register rm)
	{
		return register_decode_base(reg)<<3 | (mod<<6) | register_decode_base(rm)<<0;
	}
	/**
	 * @brief this is short hand for modRM(reg,AddressingMode::RegisterDirect,rm)
	 * 
	 * @param reg reg operrand
	 * @param rm reg/mem opperand
	 * @return amd64 modRM byte ready for execution
	 *
	 */
	inline byte modRM(Register reg,Register rm)
	{
		return modRM(reg,AddressingMode::RegisterDirect,rm);
	}
	/**
	 * @brief
	 * 
	 * @param scale must be either 1,2,4 or 8
	 * @param index register holding the index
	 * @param base register holding the base address
	 * @return amd64 SIB byte ready for execution
	 */
	inline byte SIB(uint8_t scale, Register index, Register base)
	{
		return (scale<<6) | (index<<3) | (base<<0);
	}

	namespace decode {
		namespace modrm {
			inline Register reg(byte modrm,byte rex) {
				return (Register)(
					register_encode_cpl(3)
					| register_encode_base((modrm & 0b00111000)>>3)
					| ((rex&1<<2) != 0 ? register_encode_rex() : 0)
				);
			}
			inline Register rm(byte modrm,byte rex) {
				return (Register)(
					register_encode_cpl(3)
					| register_encode_base((modrm & 0b00000111)>>0)
					| ((rex&1<<0) != 0 ? register_encode_rex() : 0)
				);
			}
			inline AddressingMode mod(byte modrm) {
				return (AddressingMode)((modrm & 0b11000000)>>6);
			}
		}
	}

	enum class Condition {
		Overflow 		= 0x0,
		NotOverflow		= 0x1,
		Below			= 0x2,
		Carry			= 0x2,
		NotAboveOrEqual	= 0x2,
		NotBelow		= 0x3,
		NotCarry		= 0x3,
		AboveOrEqual	= 0x3,
		Zero			= 0x4,
		Equal			= 0x4,
		NotZero			= 0x5,
		NotEqual		= 0x5,
		BelowOrEqual	= 0x6,
		NotAbove		= 0x6,
		NotBelowOrEqual	= 0x7,
		Above			= 0x7,
		Sign			= 0x8,
		NotSign			= 0x9,
		Parity			= 0xA,
		ParityEven		= 0xA,
		NotParity		= 0xB,
		ParityOdd		= 0xB,
		Less			= 0xC,
		NotGreaterOrEqual=0xC,
		NotLess			= 0xD,
		GreaterOrEqual	= 0xD,
		LessOrEqual		= 0xE,
		NotGreater		= 0xE,
		NotLessOrEqual	= 0xF,
		Greater			= 0xF
	};
	
	namespace prefix
	{
		/**
		* @brief constructs a REX prefix
		* 
		* @param W operation size
		* @param R extends modrm.reg
		* @param X extends sib.index
		* @param B extends modrm.rm
		* @return amd64 REX byte ready for execution
		*/
		inline byte REX(bool W, bool R, bool X, bool B) {
			return 0x40 | (W<<3) | (R<<2) | (X<<1) | (B<<0);
		}
		/**
		* @brief initiates a 2 byte VEX escape sequence
		*/
		constexpr byte VEX_2byte = 0xC5;
		/**
		* @brief initiates a 3 byte VEX escape sequence
		*/
		constexpr byte VEX_3byte = 0xC4;
		/**
		* @brief initiates a 3 byte XOP escape sequence
		*/
		constexpr byte XOP = 0x8F;
		namespace legacy
		{
			/**
			* @brief AMD64 specification: 
			`
			In 64-bit mode, the prefix allows mixing of 16-bit, 32-bit, and 64-bit data on an instruction-byinstruction basis.
			`
			... 
			`
			In 64-bit mode, most instructions default to a 32-bit operand size. For these instructions, a REX prefix
			can specify a 64-bit operand size, and a 66h prefix specifies a 16-bit operand size. The REX
			prefix takes precedence over the 66h prefix. However, if an instruction defaults to a 64-bit operand
			size, it does not need a REX prefix and it can only be overridden to a 16-bit operand size. It cannot be
			overridden to a 32-bit operand size, because there is no 32-bit operand-size override prefix in 64-bit
			mode.
			`
			...
			`
			Instructions that Cannot Use the Operand-Size Prefix: The operand-size prefix should be used
			only with general-purpose instructions and the x87 FLDENV, FNSTENV, FNSAVE, and FRSTOR
			instructions, in which the prefix selects between 16-bit and 32-bit operand size. The prefix is ignored
			by all other x87 instructions and by 64-bit media floating-point (3DNow!™) instructions.
			For other instructions (mostly SIMD instructions) the 66h, F2h, and F3h prefixes are used as opcode
			extensions to extend the instruction encoding space in the 0Fh, 0F_38h, and 0F_3Ah opcode maps.
			`
			*/
			constexpr byte OperandSizeOverride = 0x66;
			/**
			* @brief 
			* 
			*/
			constexpr byte AddressSizeOverride = 0x67;
			/**
			* @brief AMD64 specification:
			`
			Segment Overrides in 64-Bit Mode: 
			In 64-bit mode, the CS, DS, ES, and SS segment-override
			prefixes have no effect. These four prefixes are not treated as segment-override prefixes for the
			purposes of multiple-prefix rules. Instead, they are treated as null prefixes.
			The FS and GS segment-override prefixes are treated as true segment-override prefixes in 64-bit
			mode. Use of the FS or GS prefix causes their respective segment bases to be added to the effective
			address calculation. See “FS and GS Registers in 64-Bit Mode” in APM Volume 2 for details. 
			`
			*/
			namespace SegmentOverride
			{
				constexpr byte cs = 0x2E;
				constexpr byte ds = 0x3E;
				constexpr byte es = 0x26;
				constexpr byte fs = 0x64;
				constexpr byte gs = 0x65;
				constexpr byte ss = 0x36;
			}
			/**
			* @brief AMD64 specification:
			`
			The LOCK prefix causes certain kinds of memory read-modify-write instructions to occur atomically.
			`
			...
			`
			The prefix is intended to give the processor exclusive use of shared memory in a multiprocessor system.
			`
			...
			`
			The LOCK prefix can only be used with forms of the following instructions that write a memory
			operand: ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B, DEC,
			INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG, and XOR. An invalid-opcode exception occurs if
			the LOCK prefix is used with any other instruction. 
			`
			*/
			constexpr byte LOCK = 0xF0;
			/**
			* @brief AMD64 specification:
			`
			The repeat prefixes cause repetition of certain instructions that load, store, move, input, or output
			strings. The prefixes should only be used with such string instructions. Two pairs of repeat prefixes,
			REPE/REPZ and REPNE/REPNZ, perform the same repeat functions for certain compare-string and
			scan-string instructions. The repeat function uses rCX as a count register. The size of rCX is based on
			address size,
			`
			...
			`
			The REP prefix repeats its associated string instruction the number of times specified in the
			counter register (rCX). It terminates the repetition when the value in rCX reaches 0. The prefix can be
			used with the INS, LODS, MOVS, OUTS, and STOS instructions.
			`
			*/
			constexpr byte REP  = 0xF3;
			/**
			* @brief AMD64 specification:
			`
			The repeat prefixes cause repetition of certain instructions that load, store, move, input, or output
			strings. The prefixes should only be used with such string instructions. Two pairs of repeat prefixes,
			REPE/REPZ and REPNE/REPNZ, perform the same repeat functions for certain compare-string and
			scan-string instructions. The repeat function uses rCX as a count register. The size of rCX is based on
			address size,
			`
			...
			`
			REPE and REPZ are synonyms and have identical opcodes. These prefixes repeat
			their associated string instruction the number of times specified in the counter register (rCX). The
			repetition terminates when the value in rCX reaches 0 or when the zero flag (ZF) is cleared to 0. The
			REPE and REPZ prefixes can be used with the CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB,
			SCASD, and SCASW instructions.
			`
			*/
			constexpr byte REPE = 0xF3;
			/**
			* @brief AMD64 specification:
			`
			The repeat prefixes cause repetition of certain instructions that load, store, move, input, or output
			strings. The prefixes should only be used with such string instructions. Two pairs of repeat prefixes,
			REPE/REPZ and REPNE/REPNZ, perform the same repeat functions for certain compare-string and
			scan-string instructions. The repeat function uses rCX as a count register. The size of rCX is based on
			address size,
			`
			...
			`
			REPE and REPZ are synonyms and have identical opcodes. These prefixes repeat
			their associated string instruction the number of times specified in the counter register (rCX). The
			repetition terminates when the value in rCX reaches 0 or when the zero flag (ZF) is cleared to 0. The
			REPE and REPZ prefixes can be used with the CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB,
			SCASD, and SCASW instructions.
			`
			*/
			constexpr byte REPZ = 0xF3;
			/**
			* @brief AMD64 specification:
			`
			The repeat prefixes cause repetition of certain instructions that load, store, move, input, or output
			strings. The prefixes should only be used with such string instructions. Two pairs of repeat prefixes,
			REPE/REPZ and REPNE/REPNZ, perform the same repeat functions for certain compare-string and
			scan-string instructions. The repeat function uses rCX as a count register. The size of rCX is based on
			address size,
			`
			...
			`
			REPNE and REPNZ are synonyms and have identical opcodes. These prefixes
			repeat their associated string instruction the number of times specified in the counter register (rCX).
			The repetition terminates when the value in rCX reaches 0 or when the zero flag (ZF) is set to 1. The
			REPNE and REPNZ prefixes can be used with the CMPS, CMPSB, CMPSD, CMPSW, SCAS,
			SCASB, SCASD, and SCASW instructions.
			`
			*/
			constexpr byte REPNE= 0xF2;
			/**
			* @brief AMD64 specification:
			`
			The repeat prefixes cause repetition of certain instructions that load, store, move, input, or output
			strings. The prefixes should only be used with such string instructions. Two pairs of repeat prefixes,
			REPE/REPZ and REPNE/REPNZ, perform the same repeat functions for certain compare-string and
			scan-string instructions. The repeat function uses rCX as a count register. The size of rCX is based on
			address size,
			`
			...
			`
			REPNE and REPNZ are synonyms and have identical opcodes. These prefixes
			repeat their associated string instruction the number of times specified in the counter register (rCX).
			The repetition terminates when the value in rCX reaches 0 or when the zero flag (ZF) is set to 1. The
			REPNE and REPNZ prefixes can be used with the CMPS, CMPSB, CMPSD, CMPSW, SCAS,
			SCASB, SCASD, and SCASW instructions.
			`
			*/
			constexpr byte REPNZ= 0xF2;
		}
	}
	
	namespace opcode
	{
		namespace add{
			constexpr byte rm8__r8 = 0x00;
			constexpr byte rm16_32_64__r16_32_64 = 0x01;
			constexpr byte r8__rm8 = 0x02;
			constexpr byte r16_32_64__rm16_32_64 = 0x03;
			constexpr byte AL__imm8 = 0x04;
			constexpr byte rAX__imm16_32 = 0x05;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace _or{
			constexpr byte rm8__r8 = 0x08;
			constexpr byte rm16_32_64__r16_32_64 = 0x09;
			constexpr byte r8__rm8 = 0x0A;
			constexpr byte r16_32_64__rm16_32_64 = 0x0B;
			constexpr byte AL__imm8 = 0x0C;
			constexpr byte rAX__imm16_32 = 0x0D;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace adc{
			constexpr byte rm8__r8 = 0x10;
			constexpr byte rm16_32_64__r16_32_64 = 0x11;
			constexpr byte r8__rm8 = 0x12;
			constexpr byte r16_32_64__rm16_32_64 = 0x13;
			constexpr byte AL__imm8 = 0x14;
			constexpr byte rAX__imm16_32 = 0x15;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace sbb{
			constexpr byte rm8__r8 = 0x18;
			constexpr byte rm16_32_64__r16_32_64 = 0x19;
			constexpr byte r8__rm8 = 0x1A;
			constexpr byte r16_32_64__rm16_32_64 = 0x1B;
			constexpr byte AL__imm8 = 0x1C;
			constexpr byte rAX__imm16_32 = 0x1D;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace _and{
			constexpr byte rm8__r8 = 0x20;
			constexpr byte rm16_32_64__r16_32_64 = 0x21;
			constexpr byte r8__rm8 = 0x22;
			constexpr byte r16_32_64__rm16_32_64 = 0x23;
			constexpr byte AL__imm8 = 0x24;
			constexpr byte rAX__imm16_32 = 0x25;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace sub{
			constexpr byte rm8__r8 = 0x28;
			constexpr byte rm16_32_64__r16_32_64 = 0x29;
			constexpr byte r8__rm8 = 0x2A;
			constexpr byte r16_32_64__rm16_32_64 = 0x2B;
			constexpr byte AL__imm8 = 0x2C;
			constexpr byte rAX__imm16_32 = 0x2D;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace _xor{
			constexpr byte rm8__r8 = 0x30;
			constexpr byte rm16_32_64__r16_32_64 = 0x31;
			constexpr byte r8__rm8 = 0x32;
			constexpr byte r16_32_64__rm16_32_64 = 0x33;
			constexpr byte AL__imm8 = 0x34;
			constexpr byte rAX__imm16_32 = 0x35;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace cmp{
			constexpr byte rm8__r8 = 0x38;
			constexpr byte rm16_32_64__r16_32_64 = 0x39;
			constexpr byte r8__rm8 = 0x3A;
			constexpr byte r16_32_64__rm16_32_64 = 0x3B;
			constexpr byte AL__imm8 = 0x3C;
			constexpr byte rAX__imm16_32 = 0x3D;
			constexpr byte rm8__imm8 = 0x80;
			constexpr byte rm16_32_64__imm16_32 = 0x81;
			constexpr byte rm16_32_64__imm8 = 0x83;
		}
		namespace movsxd{
			constexpr byte r32_64__rm32 = 0x63;
		}
		namespace push{
			constexpr byte imm16_32 = 0x68;
			constexpr byte imm8 = 0x6A;
			constexpr byte rm16_32 = 0xFF;
			constexpr byte rm64_16 = 0xFF;
		}
		namespace imul{
			constexpr byte r16_32_64__rm16_32_64__imm16_32 = 0x69;
			constexpr byte r16_32_64__rm16_32_64__imm8 = 0x6B;
			constexpr byte AX__AL__rm8 = 0xF6;
			constexpr byte rDX__rAX__rm16_32_64 = 0xF7;
		}
		namespace ins{
			constexpr byte m8__DX = 0x6C;
			constexpr byte m16__DX = 0x6D;
			constexpr byte m16_32__DX = 0x6D;
		}
		namespace outs{
			constexpr byte DX__m8 = 0x6E;
			constexpr byte DX__m16 = 0x6F;
			constexpr byte DX__m16_32 = 0x6F;
		}
		namespace jcc {
			constexpr byte rel8off(Condition cc){return (0x70)|((uint8_t)cc);}
		}
		namespace test{
			constexpr byte rm8__r8 = 0x84;
			constexpr byte rm16_32_64__r16_32_64 = 0x85;
			constexpr byte AL__imm8 = 0xA8;
			constexpr byte rAX__imm16_32 = 0xA9;
			constexpr byte rm8__imm8 = 0xF6;
			constexpr byte rm16_32_64__imm16_32 = 0xF7;
		}
		namespace xchg{
			constexpr byte r8__rm8 = 0x86;
			constexpr byte r16_32_64__rm16_32_64 = 0x87;
		}
		namespace mov{
			constexpr byte rm8__r8 = 0x88;
			constexpr byte rm16_32_64__r16_32_64 = 0x89;
			constexpr byte r8__rm8 = 0x8A;
			constexpr byte r16_32_64__rm16_32_64 = 0x8B;
			constexpr byte m16__Sreg = 0x8C;
			constexpr byte Sreg__rm16 = 0x8E;
			constexpr byte AL__moffs8 = 0xA0;
			constexpr byte rAX__moffs16_32_64 = 0xA1;
			constexpr byte moffs8__AL = 0xA2;
			constexpr byte moffs16_32_64__rAX = 0xA3;
			constexpr byte rm8__imm8 = 0xC6;
			constexpr byte rm16_32_64__imm16_32 = 0xC7;
			constexpr byte r8__imm8 = 0xB0;
			constexpr byte r16_32_64__imm16_32_64(Register reg) {
				return 0xB8+register_decode_base(reg);
			}
		}
		namespace lea{
			constexpr byte r16_32_64__m = 0x8D;
		}
		namespace pop{
			constexpr byte rm16_32 = 0x8F;
			constexpr byte rm64_16 = 0x8F;
		}
		namespace r16_32_64{
			constexpr byte rAX = 0x90;
			constexpr byte imm16_32_64 = 0xB8;
		}
		constexpr byte nop = 0x90;
		namespace pause{
			constexpr byte _ = 0x90;
		}
		namespace cbw{
			constexpr byte AX__AL = 0x98;
		}
		namespace cwd{
			constexpr byte DX__AX = 0x99;
		}
		namespace fwait{
			constexpr byte _ = 0x9B;
		}
		namespace pushf{
			constexpr byte Flags = 0x9C;
		}
		namespace popf{
			constexpr byte Flags = 0x9D;
		}
		namespace sahf{
			constexpr byte AH = 0x9E;
		}
		namespace lahf{
			constexpr byte AH = 0x9F;
		}
		namespace movs{
			constexpr byte m8__m8 = 0xA4;
			constexpr byte m16_32_64__m16_32_64 = 0xA5;
		}
		namespace cmps{
			constexpr byte m8__m8 = 0xA6;
			constexpr byte m16_32_64__m16_32_64 = 0xA7;
		}
		namespace stos{
			constexpr byte m8__AL = 0xAA;
			constexpr byte m16_32_64__rAX = 0xAB;
		}
		namespace lods{
			constexpr byte AL__m8 = 0xAC;
			constexpr byte rAX__m16_32_64 = 0xAD;
		}
		namespace scas{
			constexpr byte m8__AL = 0xAE;
			constexpr byte m16_32_64__rAX = 0xAF;
		}
		namespace rol{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace ror{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace rcl{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace rcr{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace shl{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace shr{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace sal{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace sar{
			constexpr byte rm8__imm8 = 0xC0;
			constexpr byte rm16_32_64__imm8 = 0xC1;
			constexpr byte rm8__1 = 0xD0;
			constexpr byte rm16_32_64__1 = 0xD1;
			constexpr byte rm8__CL = 0xD2;
			constexpr byte rm16_32_64__CL = 0xD3;
		}
		namespace ret_near{
			constexpr byte imm16 = 0xC2;
			constexpr byte _ = 0xC3;
		}
		namespace enter{
			constexpr byte rBP__imm16__imm8 = 0xC8;
		}
		namespace leave{
			constexpr byte rBP = 0xC9;
		}
		namespace ret_far{
			constexpr byte imm16 = 0xCA;
			constexpr byte _ = 0xCB;
		}
		namespace _int{
			constexpr byte _3__eFlags = 0xCC;
			constexpr byte imm8__eFlags = 0xCD;
		}
		namespace into{
			constexpr byte eFlags = 0xCE;
		}
		namespace iret{
			constexpr byte Flags = 0xCF;
		}
		namespace xlat{
			constexpr byte AL__m8 = 0xD7;
		}
		namespace fadd{
			constexpr byte ST__m32real = 0xD8;
			constexpr byte ST__m64real = 0xDC;
			constexpr byte STi__ST = 0xDC;
		}
		namespace fmul{
			constexpr byte ST__m32real = 0xD8;
			constexpr byte ST__m64real = 0xDC;
			constexpr byte STi__ST = 0xDC;
		}
		namespace fcom{
			constexpr byte ST__STi_m32real = 0xD8;
			constexpr byte ST__ST1 = 0xD8;
			constexpr byte ST__m64real = 0xDC;
		}
		namespace fcomp{
			constexpr byte ST__STi_m32real = 0xD8;
			constexpr byte ST__ST1 = 0xD8;
			constexpr byte ST__m64real = 0xDC;
		}
		namespace fsub{
			constexpr byte ST__m32real = 0xD8;
			constexpr byte ST__m64real = 0xDC;
			constexpr byte STi__ST = 0xDC;
		}
		namespace fsubr{
			constexpr byte ST__m32real = 0xD8;
			constexpr byte STi__ST = 0xDC;
			constexpr byte ST__m64real = 0xDC;
		}
		namespace fdiv{
			constexpr byte ST__m32real = 0xD8;
			constexpr byte ST__m64real = 0xDC;
			constexpr byte STi__ST = 0xDC;
		}
		namespace fdivr{
			constexpr byte ST__m32real = 0xD8;
			constexpr byte STi__ST = 0xDC;
			constexpr byte ST__m64real = 0xDC;
		}
		namespace fld{
			constexpr byte ST__STi_m32real = 0xD9;
			constexpr byte ST__m80real = 0xDB;
			constexpr byte ST__m64real = 0xDD;
		}
		namespace fxch{
			constexpr byte ST__STi = 0xD9;
			constexpr byte ST__ST1 = 0xD9;
		}
		namespace fst{
			constexpr byte m32real__ST = 0xD9;
			constexpr byte m64real__ST = 0xDD;
			constexpr byte ST__STi = 0xDD;
		}
		namespace fnop{
			constexpr byte _ = 0xD9;
		}
		namespace fstp{
			constexpr byte m32real__ST = 0xD9;
			constexpr byte m80real__ST = 0xDB;
			constexpr byte m64real__ST = 0xDD;
			constexpr byte ST__STi = 0xDD;
		}
		namespace fstp1{
			constexpr byte STi__ST = 0xD9;
		}
		namespace fldenv{
			constexpr byte m14_28 = 0xD9;
		}
		namespace fchs{
			constexpr byte ST = 0xD9;
		}
		namespace fabs{
			constexpr byte ST = 0xD9;
		}
		namespace ftst{
			constexpr byte ST = 0xD9;
		}
		namespace fxam{
			constexpr byte ST = 0xD9;
		}
		namespace fldcw{
			constexpr byte m16 = 0xD9;
		}
		namespace fld1{
			constexpr byte ST = 0xD9;
		}
		namespace fldl2t{
			constexpr byte ST = 0xD9;
		}
		namespace fldl2e{
			constexpr byte ST = 0xD9;
		}
		namespace fldpi{
			constexpr byte ST = 0xD9;
		}
		namespace fldlg2{
			constexpr byte ST = 0xD9;
		}
		namespace fldln2{
			constexpr byte ST = 0xD9;
		}
		namespace fldz{
			constexpr byte ST = 0xD9;
		}
		namespace fnstenv{
			constexpr byte m14_28 = 0xD9;
		}
		namespace fstenv{
			constexpr byte m14_28 = 0xD9;
		}
		namespace f2xm1{
			constexpr byte ST = 0xD9;
		}
		namespace fyl2x{
			constexpr byte ST1__ST = 0xD9;
		}
		namespace fptan{
			constexpr byte ST = 0xD9;
		}
		namespace fpatan{
			constexpr byte ST1__ST = 0xD9;
		}
		namespace fxtract{
			constexpr byte ST = 0xD9;
		}
		namespace fprem1{
			constexpr byte ST__ST1 = 0xD9;
		}
		namespace fdecstp{
			constexpr byte _ = 0xD9;
		}
		namespace fincstp{
			constexpr byte _ = 0xD9;
		}
		namespace fnstcw{
			constexpr byte m16 = 0xD9;
		}
		namespace fstcw{
			constexpr byte m16 = 0xD9;
		}
		namespace fprem{
			constexpr byte ST__ST1 = 0xD9;
		}
		namespace fyl2xp1{
			constexpr byte ST1__ST = 0xD9;
		}
		namespace fsqrt{
			constexpr byte ST = 0xD9;
		}
		namespace fsincos{
			constexpr byte ST = 0xD9;
		}
		namespace frndint{
			constexpr byte ST = 0xD9;
		}
		namespace fscale{
			constexpr byte ST__ST1 = 0xD9;
		}
		namespace fsin{
			constexpr byte ST = 0xD9;
		}
		namespace fcos{
			constexpr byte ST = 0xD9;
		}
		namespace fiadd{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fcmovb{
			constexpr byte ST__STi = 0xDA;
		}
		namespace fimul{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fcmove{
			constexpr byte ST__STi = 0xDA;
		}
		namespace ficom{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fcmovbe{
			constexpr byte ST__STi = 0xDA;
		}
		namespace ficomp{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fcmovu{
			constexpr byte ST__STi = 0xDA;
		}
		namespace fisub{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fisubr{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fucompp{
			constexpr byte ST__ST1 = 0xDA;
		}
		namespace fidiv{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fidivr{
			constexpr byte ST__m32int = 0xDA;
			constexpr byte ST__m16int = 0xDE;
		}
		namespace fild{
			constexpr byte ST__m32int = 0xDB;
			constexpr byte ST__m16int = 0xDF;
			constexpr byte ST__m64int = 0xDF;
		}
		namespace fcmovnb{
			constexpr byte ST__STi = 0xDB;
		}
		namespace fisttp{
			constexpr byte m32int__ST = 0xDB;
			constexpr byte m64int__ST = 0xDD;
			constexpr byte m16int__ST = 0xDF;
		}
		namespace fcmovne{
			constexpr byte ST__STi = 0xDB;
		}
		namespace fist{
			constexpr byte m32int__ST = 0xDB;
			constexpr byte m16int__ST = 0xDF;
		}
		namespace fcmovnbe{
			constexpr byte ST__STi = 0xDB;
		}
		namespace fistp{
			constexpr byte m32int__ST = 0xDB;
			constexpr byte m16int__ST = 0xDF;
			constexpr byte m64int__ST = 0xDF;
		}
		namespace fcmovnu{
			constexpr byte ST__STi = 0xDB;
		}
		namespace fneni {
			constexpr byte _ = 0xDB;
		}
		namespace fndisi {
			constexpr byte _ = 0xDB;
		}
		namespace fnclex{
			constexpr byte _ = 0xDB;
		}
		namespace fclex{
			constexpr byte _ = 0xDB;
		}
		namespace fninit{
			constexpr byte _ = 0xDB;
		}
		namespace finit{
			constexpr byte _ = 0xDB;
		}
		namespace fnsetpm {
			constexpr byte _ = 0xDB;
		}
		namespace fucomi{
			constexpr byte ST__STi = 0xDB;
		}
		namespace fcomi{
			constexpr byte ST__STi = 0xDB;
		}
		namespace fcom2{
			constexpr byte ST__STi = 0xDC;
		}
		namespace fcomp3{
			constexpr byte ST__STi = 0xDC;
		}
		namespace ffree{
			constexpr byte STi = 0xDD;
		}
		namespace fxch4{
			constexpr byte ST__STi = 0xDD;
		}
		namespace frstor{
			constexpr byte ST__ST1__ST2__ = 0xDD;
		}
		namespace fucom{
			constexpr byte ST__STi = 0xDD;
			constexpr byte ST__ST1 = 0xDD;
		}
		namespace fucomp{
			constexpr byte ST__STi = 0xDD;
			constexpr byte ST__ST1 = 0xDD;
		}
		namespace fnsave{
			constexpr byte m94_108__ST__ST1__ = 0xDD;
		}
		namespace fsave{
			constexpr byte m94_108__ST__ST1__ = 0xDD;
		}
		namespace fnstsw{
			constexpr byte m16 = 0xDD;
			constexpr byte AX = 0xDF;
		}
		namespace fstsw{
			constexpr byte m16 = 0xDD;
			constexpr byte AX = 0xDF;
		}
		namespace faddp{
			constexpr byte STi__ST = 0xDE;
			constexpr byte ST1__ST = 0xDE;
		}
		namespace fmulp{
			constexpr byte STi__ST = 0xDE;
			constexpr byte ST1__ST = 0xDE;
		}
		namespace fcomp5{
			constexpr byte ST__STi = 0xDE;
		}
		namespace fcompp{
			constexpr byte ST__ST1 = 0xDE;
		}
		namespace fsubrp{
			constexpr byte STi__ST = 0xDE;
			constexpr byte ST1__ST = 0xDE;
		}
		namespace fsubp{
			constexpr byte STi__ST = 0xDE;
			constexpr byte ST1__ST = 0xDE;
		}
		namespace fdivrp{
			constexpr byte STi__ST = 0xDE;
			constexpr byte ST1__ST = 0xDE;
		}
		namespace fdivp{
			constexpr byte STi__ST = 0xDE;
			constexpr byte ST1__ST = 0xDE;
		}
		namespace ffreep{
			constexpr byte STi = 0xDF;
		}
		namespace fxch7{
			constexpr byte ST__STi = 0xDF;
		}
		namespace fstp8{
			constexpr byte STi__ST = 0xDF;
		}
		namespace fstp9{
			constexpr byte STi__ST = 0xDF;
		}
		namespace fbld{
			constexpr byte ST__m80dec = 0xDF;
		}
		namespace fucomip{
			constexpr byte ST__STi = 0xDF;
		}
		namespace fbstp{
			constexpr byte m80dec__ST = 0xDF;
		}
		namespace fcomip{
			constexpr byte ST__STi = 0xDF;
		}
		namespace loopnz{
			constexpr byte rCX__rel8 = 0xE0;
		}
		namespace loopz{
			constexpr byte rCX__rel8 = 0xE1;
		}
		namespace loop{
			constexpr byte rCX__rel8 = 0xE2;
		}
		namespace jecxz{
			constexpr byte rel8__ECX = 0xE3;
		}
		namespace in{
			constexpr byte AL__imm8 = 0xE4;
			constexpr byte eAX__imm8 = 0xE5;
			constexpr byte AL__DX = 0xEC;
			constexpr byte eAX__DX = 0xED;
		}
		namespace out{
			constexpr byte imm8__AL = 0xE6;
			constexpr byte imm8__eAX = 0xE7;
			constexpr byte DX__AL = 0xEE;
			constexpr byte DX__eAX = 0xEF;
		}
		namespace call{
			constexpr byte rel16_32 = 0xE8;
			constexpr byte rm16_32_64 = 0xFF;
		}
		namespace jmp{
			constexpr byte rel16_32 = 0xE9;
			constexpr byte rel8 = 0xEB;
			constexpr byte rm16_32_64 = 0xFF;
		}
		namespace int1{
			constexpr byte eFlags = 0xF1;
		}
		namespace hlt{
			constexpr byte _ = 0xF4;
		}
		namespace cmc{
			constexpr byte _ = 0xF5;
		}
		namespace _not{
			constexpr byte rm8 = 0xF6;
			constexpr byte rm16_32_64 = 0xF7;
		}
		namespace neg{
			constexpr byte rm8 = 0xF6;
			constexpr byte rm16_32_64 = 0xF7;
		}
		namespace mul{
			constexpr byte AX__AL__rm8 = 0xF6;
			constexpr byte rDX__rAX__rm16_32_64 = 0xF7;
		}
		namespace div{
			constexpr byte AL__AH__AX__rm8 = 0xF6;
			constexpr byte rDX__rAX__rm16_32_64 = 0xF7;
		}
		namespace idiv{
			constexpr byte AL__AH__AX__rm8 = 0xF6;
			constexpr byte rDX__rAX__rm16_32_64 = 0xF7;
		}
		namespace clc{
			constexpr byte _ = 0xF8;
		}
		namespace stc{
			constexpr byte _ = 0xF9;
		}
		namespace cli{
			constexpr byte _ = 0xFA;
		}
		namespace sti{
			constexpr byte _ = 0xFB;
		}
		namespace cld{
			constexpr byte _ = 0xFC;
		}
		namespace std{
			constexpr byte _ = 0xFD;
		}
		namespace inc{
			constexpr byte rm8 = 0xFE;
			constexpr byte rm16_32_64 = 0xFF;
		}
		namespace dec{
			constexpr byte rm8 = 0xFE;
			constexpr byte rm16_32_64 = 0xFF;
		}
		namespace callf{
			constexpr byte m16_32_64 = 0xFF;
		}
		namespace jmpf{
			constexpr byte m16_32_64 = 0xFF;
		}
		/**
			@brief opcodes in this namespace need to be prefixed with 0x0F
		*/
		namespace secondary
		{
			constexpr byte syscall = 0x05;
			namespace jcc {
				constexpr byte rel16_32off(Condition cc){return (0x80)|((uint8_t)cc);}
			}
		}
	}
}
