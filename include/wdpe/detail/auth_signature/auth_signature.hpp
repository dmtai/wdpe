/**
 * @file auth_signature.hpp
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <wdpe/detail/pe/pe_parser.hpp>
#include <wdpe/detail/utils/file_utils.hpp>

namespace wdpe {
namespace detail {
namespace auth_signature {

inline void delete_signature(std::fstream& fs,
                             const image_data_directory& dir_entry_sec,
                             uint32_t dir_entry_sec_addr,
                             const std::string& file_path) {
  file_utils::resize_file(file_path, dir_entry_sec.virtual_address);

  const uint32_t virtual_address{0};
  fs.seekg(dir_entry_sec_addr);
  fs.write(reinterpret_cast<const char*>(&virtual_address),
           sizeof(virtual_address));

  const uint32_t size{0};
  fs.write(reinterpret_cast<const char*>(&size), sizeof(size));
}

}  // namespace auth_signature
}  // namespace detail
}  // namespace wdpe