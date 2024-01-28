/**
 * @file utils.hpp
 */

#pragma once

#include <wdpe/detail/pe/pe_parser.hpp>
#include <wdpe/exceptions.hpp>
#include <wdpe/pe.hpp>

namespace wdpe {
namespace detail {
namespace pe {

inline void validate_section_position(const image_data_directory& dir_entry_sec,
                                      size_t file_size) {
  const auto payload_end_addr =
      dir_entry_sec.virtual_address + dir_entry_sec.size;
  if (payload_end_addr != file_size) {
    throw unknown_file_format{
        "Data stored at the security directory "
        "file offset not at the end of the file."};
  }
}

inline bool is_empty(const image_data_directory& dir_entry_sec) {
  return dir_entry_sec.virtual_address == 0 || dir_entry_sec.size == 0;
}

}  // namespace pe
}  // namespace detail
}  // namespace wdpe