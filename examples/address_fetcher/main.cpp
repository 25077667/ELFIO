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

#include <elfio/elf_types.hpp>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

class AccessorAdaptor
{
  public:
    AccessorAdaptor() = default;
    explicit AccessorAdaptor( const ELFIO::elfio&   elf,
                              const ELFIO::section* section )
    {
        my_type = section->get_type();
        switch ( my_type ) {
        case ELFIO::SHT_DYNAMIC:
            accessor.emplace<ELFIO::dynamic_section_accessor>( elf, section );
            break;
        case ELFIO::SHT_DYNSYM:
        case ELFIO::SHT_SYMTAB:
            accessor.emplace<ELFIO::symbol_section_accessor>( elf, section );
            break;
        case ELFIO::SHT_GNU_versym:
            accessor.emplace<ELFIO::versym_section_accessor>( elf, section );
            break;
        case ELFIO::SHT_GNU_verneed:
            accessor.emplace<ELFIO::versym_r_section_accessor>( elf, section );
            break;
        case ELFIO::SHT_RELA:
            accessor.emplace<ELFIO::relocation_section_accessor>( elf,
                                                                  section );
            break;
        case ELFIO::SHT_NOTE:
            accessor.emplace<ELFIO::note_section_accessor>( elf, section );
            break;
        case ELFIO::SHT_STRTAB:
            accessor.emplace<ELFIO::string_section_accessor>( elf, section );
            break;
        default:
            // Use monostate for other types or unsupported types
            accessor.emplace<std::monostate>();
            break;
        }
    }
    // copy constructor
    AccessorAdaptor( const AccessorAdaptor& other )
        : my_type( other.my_type ), accessor( other.accessor )
    {
    }
    // move constructor
    AccessorAdaptor( AccessorAdaptor&& other ) noexcept
        : my_type( other.my_type ), accessor( other.accessor )
    {
    }
    // copy assignment
    AccessorAdaptor& operator=( const AccessorAdaptor& other )
    {
        if ( this != &other ) {
            my_type  = other.my_type;
            accessor = other.accessor;
        }
        return *this;
    }
    // move assignment
    AccessorAdaptor& operator=( AccessorAdaptor&& other ) noexcept
    {
        if ( this != &other ) {
            my_type  = other.my_type;
            accessor = other.accessor;
        }
        return *this;
    }

    template <typename T> T* get() noexcept
    {
        return std::get_if<T>( &accessor );
    }

  private:
    std::variant<std::monostate,
                 ELFIO::dynamic_section_accessor,
                 ELFIO::modinfo_section_accessor,
                 ELFIO::note_section_accessor,
                 ELFIO::relocation_section_accessor,
                 ELFIO::string_section_accessor,
                 ELFIO::symbol_section_accessor,
                 ELFIO::versym_section_accessor,
                 ELFIO::versym_r_section_accessor>
        accessor;

    ELFIO::Elf_Word my_type = 0;
};
class SectionView
{
  public:
    SectionView() = default;
    SectionView( const ELFIO::elfio& elf, const ELFIO::section* sec )
        : section( sec ), accessor_adaptor( elf, sec )
    {
    }
    // copy constructor
    SectionView( const SectionView& other )
        : section( other.section ), accessor_adaptor( other.accessor_adaptor )
    {
    }
    // move constructor
    SectionView( SectionView&& other ) noexcept
        : section( other.section ), accessor_adaptor( other.accessor_adaptor )
    {
    }
    // copy assignment
    SectionView& operator=( const SectionView& other )
    {
        if ( this != &other ) {
            section          = other.section;
            accessor_adaptor = other.accessor_adaptor;
        }
        return *this;
    }
    // move assignment
    SectionView& operator=( SectionView&& other ) noexcept
    {
        if ( this != &other ) {
            section          = other.section;
            accessor_adaptor = other.accessor_adaptor;
        }
        return *this;
    }

    template <typename T> T* getAccessor() noexcept
    {
        return accessor_adaptor.get<T>();
    }
    const ELFIO::section* getSection() const noexcept { return section; }

  private:
    const ELFIO::section* section = nullptr;
    AccessorAdaptor       accessor_adaptor;
};
class ELFHandler
{
  public:
    ELFHandler( const std::string& file_name )
        : reader( []( const std::string& file_name ) -> ELFIO::elfio {
              ELFIO::elfio reader;
              if ( !reader.load( file_name ) ) {
                  throw std::runtime_error(
                      "File not found or it is not an ELF file" );
              }
              return reader;
          }( file_name ) )
    {
        // Cache all section accessors in the section_table
        // This allows us to access the section_accessor by the section name directly
        std::for_each( reader.sections.begin(), reader.sections.end(),
                       [this]( const auto& sec ) {
                           section_table[sec->get_name()] =
                               SectionView( reader, sec.get() );
                       } );
    }

    /**
     * @brief Destructor for ELFHandler.
     * We should ensure that the section_table (the unordered_map) is cleared before the reader (the ELFIO object) is destructed.
     */
    ~ELFHandler() { section_table.clear(); }

    std::pair<uint64_t, uint64_t> getBeginEndAddr() noexcept
    {
        if ( vmp_begin_addr == -1 || vmp_end_addr == -1 ) {
            const auto& [begin_addr, end_addr] = doGetBeginEndAddr();
            vmp_begin_addr                     = begin_addr;
            addr                               = end_addr;
        }

        return { vmp_begin_addr, vmp_end_addr };
    }

    /**
     * @brief Get the entire chuck of the .text section.
     */
    std::vector<uint8_t> getTextSection() noexcept
    {
        const auto& chunk = doGetTextSection();
        if ( chunk.empty() ) {
            std::cerr << "Error: Could not find the .text section" << std::endl;
            return {};
        }

        return chunk;
    }

  private:
    ELFIO::elfio                                 reader;
    std::unordered_map<std::string, SectionView> section_table;
    uint64_t                                     vmp_begin_addr = -1;
    uint64_t                                     vmp_end_addr   = -1;

  private:
    /**
     * Retrieves the index of an entry in the ".dynsym" section based on its signature.
     *
     * @param signature The signature of the entry to search for.
     * @return The index of the entry if found, or -1 if not found.
     */
    uint64_t getEntryIndex( const std::string& signature ) noexcept
    {
        const auto& accessor_iter = section_table.find( ".dynsym" );
        if ( accessor_iter == section_table.end() ) {
            return -1;
        }

        const auto& accessor =
            accessor_iter->second.getAccessor<ELFIO::symbol_section_accessor>();
        auto size = accessor.get_symbols_num();
        for ( size_t i = 0; i < size; i++ ) {
            ELFIO::Elf64_Addr value = -1;
            std::string       name;
            ELFIO::Elf_Xword  size          = 0;
            unsigned char     bind          = 0;
            unsigned char     type          = 0;
            ELFIO::Elf_Half   section_index = 0;
            unsigned char     other         = 0;

            accessor.get_symbol( i, name, value, size, bind, type,
                                 section_index, other );
            if ( name == signature )
                return i;
        }

        return -1;
    }

    /**
     * @brief Retrieves the index of an entry in the ".rela.plt" section based on the index of the entry in the ".dynsym" section.
     *        This is used to find the index of the ".plt" section.
     * 
     * @param dynsym_idx The index of the entry in the ".dynsym" section.
     * @return The index of the entry in the ".rela.plt" section if found, or -1 if not found.
     */
    uint64_t getRelapltIdx( uint64_t dynsym_idx ) noexcept
    {
        const auto& accessor_iter = section_table.find( ".rela.plt" );
        if ( accessor_iter == section_table.end() ) {
            return -1;
        }

        uint64_t    relaplt_idx = -1;
        const auto& accessor =
            accessor_iter->second
                .getAccessor<ELFIO::relocation_section_accessor>();
        auto size = accessor.get_entries_num();
        for ( size_t i = 0; i < size; i++ ) {
            ELFIO::Elf64_Addr offset = 0;
            ELFIO::Elf_Word   symbol = 0;
            ELFIO::Elf_Word   type   = 0;
            int64_t           addend = 0;

            accessor.get_entry( i, offset, symbol, type, addend );

            if ( symbol == dynsym_idx ) {
                relaplt_idx = i;
                break;
            }
        }

        return relaplt_idx;
    }

    /**
     * @brief Retrieves the address of an entry in the ".plt" section based on the index of the entry in the ".rela.plt" section.
     * 
     * @param relaplt_idx The index of the entry in the ".rela.plt" section.
     * @return The address of the entry in the ".plt" section if found, or -1 if not found.
     */
    uint64_t getPltAddr( uint64_t relaplt_idx ) noexcept
    {
        const auto& plt_section_iter = section_table.find( ".plt" );
        if ( plt_section_iter == section_table.end() ) {
            return -1;
        }

        const auto* const plt_sec       = plt_section_iter->second.getSection();
        uint64_t          alignment     = plt_sec->get_addr_align();
        uint64_t          plt_base_addr = plt_sec->get_address();

        // if there is an entry with index k on the .rela.plt section, which Info is vmp_begin_idx<a_type_byte>
        // than the index of the .plt section is k + 1
        return plt_base_addr + alignment * ( relaplt_idx + 1 );
    }

    /**
     * @brief Get the begin and end address of the VMPilot signatures.
     */
    std::pair<uint64_t, uint64_t> doGetBeginEndAddr() noexcept
    {
        // Step 1: get the index of begin and end with getEntryIndex
        uint64_t begin_dynsym_idx =
            getEntryIndex( VMPilot::Common::BEGIN_VMPILOT_SIGNATURE );
        uint64_t end_dynsym_idx =
            getEntryIndex( VMPilot::Common::END_VMPILOT_SIGNATURE );
        if ( begin_dynsym_idx == -1 || end_dynsym_idx == -1 ) {
            std::cerr << "Error: Could not find the VMPilot signatures in the "
                         ".dynsym section"
                      << std::endl;
            return { -1, -1 };
        }

        // Step 2: get the index of the .rela.plt section
        uint64_t begin_relaplt_idx = getRelapltIdx( begin_dynsym_idx );
        uint64_t end_relaplt_idx   = getRelapltIdx( end_dynsym_idx );
        if ( begin_relaplt_idx == -1 || end_relaplt_idx == -1 ) {
            std::cerr << "Error: Could not find the VMPilot signatures in the "
                         ".rela.plt section"
                      << std::endl;
            return { -1, -1 };
        }

        // Step 3: get the base address and alignment of the .plt section
        uint64_t begin_addr = getPltAddr( begin_relaplt_idx );
        uint64_t end_addr   = getPltAddr( end_relaplt_idx );
        if ( begin_addr == -1 || end_addr == -1 ) {
            std::cerr << "Error: Could not find the .plt section" << std::endl;
            return { -1, -1 };
        }

        return { begin_addr, end_addr };
    }

    /**
     * @brief Get the entire chuck of the .text section.
     */
    std::vector<uint8_t> doGetTextSection() noexcept
    {
        const auto& text_section_iter = section_table.find( ".text" );
        if ( text_section_iter == section_table.end() ) {
            return {};
        }

        const auto* const    section = text_section_iter->second.getSection();
        std::vector<uint8_t> text_section( section->get_size() );
        std::memcpy( text_section.data(), section->get_address(),
                     section->get_size() );

        return text_section;
    }
};

void fetchAddress( ELFHandler& elf_handler ) noexcept
{
    const auto& [begin_addr, end_addr] = elf_handler.getBeginEndAddr();
    std::cout << "Begin address: " << std::hex << begin_addr << std::endl;
    std::cout << "End address: " << std::hex << end_addr << std::endl;
}

void disassembleTextSection( ELFHandler& elf_handler ) noexcept
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
        ELFHandler elf_handler( std::string( argv[1] ) );
        fetchAddress( elf_handler );
        disassembleTextSection( elf_handler );
    }
    catch ( const std::exception& e ) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
