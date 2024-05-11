#ifndef __SECTION_VIEWER_HPP__
#define __SECTION_VIEWER_HPP__
#pragma once

#include <elfio/elf_types.hpp>
#include <elfio/elfio.hpp>

#include <memory>
#include <string>
#include <vector>

namespace scc {

/**
 * @brief A viewer class for the ELFIO::section class.
 * 
 * we not take ownership of the section object.
 * This class is used to provide a more convenient way to access the section object.
 */
class SectionViewer
{
  public:
    SectionViewer() = default;
    SectionViewer( ELFIO::section* sec ) : section( sec ) {}

    SectionViewer( const SectionViewer& )            = delete;
    SectionViewer& operator=( const SectionViewer& ) = delete;
    SectionViewer( SectionViewer&& )                 = default;
    SectionViewer& operator=( SectionViewer&& )      = default;
    ~SectionViewer()                                 = default;

    ELFIO::section* getSection() noexcept { return section; }

  private:
    ELFIO::section* section = nullptr;
};

} // namespace scc

#endif // __SECTION_VIEWER_HPP__