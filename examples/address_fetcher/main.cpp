#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <iostream>

#include <utilities.hpp>
#include <capstone.hpp>

#include <elfio/elf_types.hpp>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

uint64_t get_entry_index( const ELFIO::symbol_section_accessor& accessor,
                          const std::string& signature ) noexcept
{
    auto size = accessor.get_symbols_num();
    for ( size_t i = 0; i < size; i++ ) {
        ELFIO::Elf64_Addr value = -1;
        std::string       name;
        ELFIO::Elf_Xword  size          = 0;
        unsigned char     bind          = 0;
        unsigned char     type          = 0;
        ELFIO::Elf_Half   section_index = 0;
        unsigned char     other         = 0;

        accessor.get_symbol( i, name, value, size, bind, type, section_index,
                             other );
        if ( name == signature )
            return i;
    }

    return -1;
}

std::pair<uint64_t, uint64_t> get_begin_end_idx_on_dynsym(
    const ELFIO::symbol_section_accessor& accessor ) noexcept
{

    if ( accessor.get_symbols_num() == 0 )
        return { 0, 0 };

    uint64_t vmp_begin_idx = 0;
    uint64_t vmp_end_idx   = 0;

    vmp_begin_idx =
        get_entry_index( accessor, VMPilot::Common::BEGIN_VMPILOT_SIGNATURE );
    vmp_end_idx =
        get_entry_index( accessor, VMPilot::Common::END_VMPILOT_SIGNATURE );

    return { vmp_begin_idx, vmp_end_idx };
}

uint64_t dynsym_idx_to_relaplt_idx( const ELFIO::elfio& elf_reader,
                                    uint64_t            dynsym_idx ) noexcept
{
    // get the index of the .rela.plt section
    uint64_t relaplt_idx = 0;
    for ( const auto& sec : elf_reader.sections ) {
        if ( ELFIO::SHT_RELA != sec->get_type() )
            continue;

        ELFIO::relocation_section_accessor rels( elf_reader, sec.get() );
        auto                               size = rels.get_entries_num();
        for ( size_t i = 0; i < size; i++ ) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word   symbol = 0;
            ELFIO::Elf_Word   type   = 0;
            int64_t           addend = 0;

            rels.get_entry( i, offset, symbol, type, addend );

            if ( symbol == dynsym_idx ) {
                relaplt_idx = i;
                break;
            }
        }
    }

    return relaplt_idx;
}

/**
 * @brief Similar to nm -d -j .plt <filename> | grep VMPilot_Begin and VMPilot_End
 */
std::pair<uint64_t, uint64_t>
get_begin_end_addr( const ELFIO::elfio& elf_reader ) noexcept
{
    uint64_t begin_dynsym_idx = 0;
    uint64_t end_dynsym_idx   = 0;
    // check if exist begin and end signature
    for ( const auto& sec : elf_reader.sections ) {
        // the VMPilot signatures are only on the .dynsym section
        if ( sec->get_name() != ".dynsym" )
            continue;

        ELFIO::symbol_section_accessor symbols( elf_reader, sec.get() );
        const auto& [begin_idx, end_idx] =
            get_begin_end_idx_on_dynsym( symbols );
        begin_dynsym_idx = begin_idx;
        end_dynsym_idx   = end_idx;
        break;
    }

    // Begin and end should appear simultaneously or not appear at all
    if ( begin_dynsym_idx == 0 || end_dynsym_idx == 0 ) {
        return { 0, 0 };
    }

    // get the index on .rel.plt section, which is the index of the .plt section
    // if there is an entry with index k on the .rel.plt section, which Info is vmp_begin_idx<a_type_byte>
    // than the index of the .plt section is k + 1
    uint64_t begin_relaplt_idx =
        dynsym_idx_to_relaplt_idx( elf_reader, begin_dynsym_idx );
    uint64_t end_relaplt_idx =
        dynsym_idx_to_relaplt_idx( elf_reader, end_dynsym_idx );
    if ( begin_relaplt_idx == -1 || end_relaplt_idx == -1 ) {
        return { 0, 0 };
    }

    // get the base address and alignment of the .plt section
    uint64_t alignment     = 0;
    uint64_t plt_base_addr = 0;
    for ( const auto& sec : elf_reader.sections ) {
        if ( ELFIO::SHT_PROGBITS != sec->get_type() )
            continue;

        if ( sec->get_name() == ".plt" ) {
            plt_base_addr = sec->get_address();
            alignment     = sec->get_addr_align();
            break;
        }
    }

    // return plt + alignment + offset
    return { plt_base_addr + alignment * ( begin_relaplt_idx + 1 ),
             plt_base_addr + alignment * ( end_relaplt_idx + 1 ) };
}

// Function to fetch the address range of VMPilot signatures
std::pair<uint64_t, uint64_t> fetch_address_range( const ELFIO::elfio& reader )
{
    const auto [begin_addr, end_addr] = get_begin_end_addr( reader );
    if ( begin_addr == 0 || end_addr == 0 ) {
        std::cerr << "Error: Could not find the VMPilot signatures"
                  << std::endl;
        return { 0, 0 };
    }

    return { begin_addr, end_addr };
}

/**
 * Retrieves the contents of the ".text" section from the given ELF file.
 * 
 * @param elf_reader The ELF file reader object.
 * @return A vector containing the contents of the ".text" section.
 */
std::vector<uint8_t> get_text_section( const ELFIO::elfio& elf_reader )
{
    ELFIO::elfio reader;

    std::vector<uint8_t> text_section;
    for ( const auto& sec : elf_reader.sections ) {
        if ( sec->get_name() == ".text" ) {
            text_section.resize( sec->get_size() );
            std::memcpy( text_section.data(), sec->get_data(),
                         sec->get_size() );
            break;
        }
    }

    return text_section;
}

int main( int argc, char** argv )
{
    // the target file is given from argc argv
    // the argv[1] is the target file, it is guaranteed to be an ELF file
    // we pass it to the elfio reader
    if ( argc != 2 ) {
        printf( "Usage: address_fetcher <file_name>\n" );
        return 1;
    }

    const std::string file_name = argv[1];
    ELFIO::elfio      reader;
    if ( !reader.load( file_name ) ) {
        std::cerr << "File " << file_name
                  << " is not found or it is not an ELF file" << std::endl;
        return 1;
    }

    // step 1: get the address range of the VMPilot signatures
    {
        const auto [begin_addr, end_addr] = fetch_address_range( reader );
        std::cout << "Begin address: " << std::hex << begin_addr << std::endl;
        std::cout << "End address: " << std::hex << end_addr << std::endl;
    }

    // step 2: disassemble the .text section
    std::vector<uint8_t> text_section = get_text_section( reader );
    {
        auto cs    = Capstone::Capstone();
        auto insns = cs.disasm( text_section );
        for ( auto& insn : insns )
            std::cout << insn.mnemonic << " " << insn.op_str << std::endl;
    }

    return 0;
}
