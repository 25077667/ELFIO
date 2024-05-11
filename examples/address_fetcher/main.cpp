#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <iostream>
#include <iomanip>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>
#include <variant>

#include <utilities.hpp>
#include <capstone.hpp>
#include <ELFHandler.hpp>

#include <elfio/elf_types.hpp>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

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
        std::cout << std::hex << std::setw( 16 ) << std::setfill( '0' )
                  << insn.address << ": " << insn.mnemonic << " " << insn.op_str
                  << std::endl;
    }
}

int main( int argc, char** argv )
{
    if ( argc != 2 ) {
        printf( "Usage: address_fetcher <file_name>\n" );
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
