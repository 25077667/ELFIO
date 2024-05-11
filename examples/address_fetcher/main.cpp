#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <iostream>
#include <iomanip>
#include <stdexcept>

#include <utilities.hpp>
#include <capstone.hpp>
#include <ELFHandler.hpp>

#include <elfio/elf_types.hpp>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

#define RED   "\033[1;31m"
#define RESET "\033[0m"

void fetchAddress( scc::ELFHandler& elf_handler ) noexcept;
void disassembleTextSection( scc::ELFHandler& elf_handler ) noexcept;
bool isCallInstruction( const Capstone::Instruction& mnemonic ) noexcept;
int  isTargetInstruction( const Capstone::Instruction& insn,
                          scc::ELFHandler&             elf_handler ) noexcept;

uint64_t nearCallExtractor( uint64_t                     text_base,
                            const Capstone::Instruction& insn ) noexcept;

uint64_t farCallExtractor( uint64_t                     text_base,
                           const Capstone::Instruction& insn ) noexcept;

int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        std::cout << "Usage: address_fetcher <file_name>" << std::endl;
        return 1;
    }

    try {
        scc::ELFHandler elf_handler( argv[1] );
        fetchAddress( elf_handler );
        disassembleTextSection( elf_handler );
    }
    catch ( const std::exception& e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}

void fetchAddress( scc::ELFHandler& elf_handler ) noexcept
{
    const auto& [begin_addr, end_addr] = elf_handler.getBeginEndAddr();
    std::cout << "Begin address: " << std::hex << begin_addr << std::endl;
    std::cout << "End address: " << std::hex << end_addr << std::endl;
}

void disassembleTextSection( scc::ELFHandler& elf_handler ) noexcept
{
    const auto& text_section = elf_handler.getTextSection();
    if ( text_section.empty() ) {
        std::cerr << "Error: Could not find the .text section" << std::endl;
        return;
    }

    auto cs    = Capstone::Capstone();
    auto insns = cs.disasm( text_section );
    for ( auto& insn : insns ) {
        auto target = isTargetInstruction( insn, elf_handler );
        if ( target == 1 || target == -1 ) {
            std::cout << RED;
        }
        else if ( target == 0 ) {
            std::cout << RESET;
        }
        std::cout << std::hex << std::setw( 16 ) << std::setfill( '0' )
                  << insn.address << ": " << insn.mnemonic << " " << insn.op_str
                  << std::endl;
    }
}

bool isCallInstruction( const Capstone::Instruction& mnemonic ) noexcept
{
    // please refer to the capstone/x86.h for more details
    constexpr auto X86_INS_CALL = 62;
    return mnemonic.id == X86_INS_CALL;
}

// is begin return 1, is end return -1, otherwise return 0
int isTargetInstruction( const Capstone::Instruction& insn,
                         scc::ELFHandler&             elf_handler ) noexcept
{
    auto is_call = isCallInstruction( insn );
    if ( !is_call )
        return 0;

    const auto& [begin_addr, end_addr] = elf_handler.getBeginEndAddr();
    const auto& text_base_addr         = elf_handler.getTextBaseAddr();

    auto op_code = insn.bytes[0];
    if ( op_code == 0xE8 ) {
        auto target_addr = nearCallExtractor( text_base_addr, insn );
        // Magic calculation to determine if the target address is the begin or end address
        return ( target_addr == begin_addr ) + ( target_addr == end_addr ) * -1;
    }
    else if ( op_code == 0x9A ) {
        auto target_addr = farCallExtractor( text_base_addr, insn );
        // Magic calculation to determine if the target address is the begin or end address
        return ( target_addr == begin_addr ) + ( target_addr == end_addr ) * -1;
    }
    else if ( op_code == 0xFF ) {
        // absolute indirect call, https://c9x.me/x86/html/file_module_x86_id_26.html
        // FF /2	CALL r/m16	Call near, absolute indirect, address given in r/m16
        // FF /2	CALL r/m32	Call near, absolute indirect, address given in r/m32
        // FF /3	CALL m16:16	Call far, absolute indirect, address given in m16:16
        // FF /3	CALL m16:32	Call far, absolute indirect, address given in m16:32

        // We use the operand to determine the size of the address
        // TODO: Implement this
        std::cerr << "Error: Absolute indirect call is not supported"
                  << std::endl;
        return 9453;
    }

    std::cerr << "Error: Unknown call instruction" << std::endl;
    return 0;
}

uint64_t nearCallExtractor( uint64_t                     text_base,
                            const Capstone::Instruction& insn ) noexcept
{
    // The operand of the near call instruction is a 32-bit relative address
    // from the next instruction
    int32_t offset = 0;
    // because the opcode is one byte, we need to skip it
    std::memcpy( &offset, insn.bytes.data() + 1, insn.size - 1 );
    return text_base + insn.address + insn.size + offset;
}

uint64_t farCallExtractor( uint64_t                     text_base,
                           const Capstone::Instruction& insn ) noexcept
{
    // The operand of the far call instruction is a 16-bit segment and a 32-bit
    // offset
    uint16_t segment = 0;
    uint32_t offset  = 0;
    // because the opcode is one byte, we need to skip it
    std::memcpy( &segment, insn.bytes.data() + 1, 2 );
    std::memcpy( &offset, insn.bytes.data() + 3, 4 );
    return ( segment << 4 ) + offset;
}
