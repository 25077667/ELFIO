#ifndef __ELF_HANDLER_HPP__
#define __ELF_HANDLER_HPP__
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <cstdint>

namespace scc {

class ELFHandler
{
  public:
    ELFHandler( const std::string& file_name );
    ~ELFHandler();

    std::pair<uint64_t, uint64_t> getBeginEndAddr() noexcept;
    std::vector<uint8_t>          getTextSection() noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;

    friend std::unique_ptr<Impl>
    make_unique_impl( const std::string& file_name );

  private:
    /**
     * Retrieves the index of an entry in the ".dynsym" section based on its signature.
     *
     * @param signature The signature of the entry to search for.
     * @return The index of the entry if found, or -1 if not found.
     */
    uint64_t getEntryIndex( const std::string& signature ) noexcept;

    /**
     * @brief Retrieves the index of an entry in the ".rela.plt" section based on the index of the entry in the ".dynsym" section.
     *        This is used to find the index of the ".plt" section.
     * 
     * @param dynsym_idx The index of the entry in the ".dynsym" section.
     * @return The index of the entry in the ".rela.plt" section if found, or -1 if not found.
     */
    uint64_t getRelapltIdx( uint64_t dynsym_idx ) noexcept;

    /**
     * @brief Retrieves the address of an entry in the ".plt" section based on the index of the entry in the ".rela.plt" section.
     * 
     * @param relaplt_idx The index of the entry in the ".rela.plt" section.
     * @return The address of the entry in the ".plt" section if found, or -1 if not found.
     */
    uint64_t getPltAddr( uint64_t relaplt_idx ) noexcept;

    /**
     * @brief Get the begin and end address of the VMPilot signatures.
     */
    virtual std::pair<uint64_t, uint64_t> doGetBeginEndAddr() noexcept;

    /**
     * @brief Get the entire chuck of the .text section.
     */
    virtual std::vector<uint8_t> doGetTextSection() noexcept;
};

} // namespace scc

#endif // __ELF_HANDLER_HPP__