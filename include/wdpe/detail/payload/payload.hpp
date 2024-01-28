/**
 * @file payload.hpp
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <wdpe/detail/crypto/checksum.hpp>
#include <wdpe/detail/pe/pe_parser.hpp>
#include <wdpe/detail/utils/file_utils.hpp>
#include <wdpe/exceptions.hpp>
#include <wdpe/pe.hpp>

namespace wdpe {
namespace detail {
namespace payload {

using buf_type = std::vector<char>;

class payload {
 public:
  payload(const char* data, uint32_t size) noexcept
      : data_{data}, data_size_{size} {}

  const char* get_data() const noexcept { return data_; }

  const uint32_t& get_data_size() const noexcept { return data_size_; }

 private:
  const char* data_;
  const uint32_t data_size_;
};

inline void delete_payload(std::fstream& fs,
                           const image_data_directory& dir_entry_sec,
                           uint32_t dir_entry_sec_size_addr,
                           const std::string& file_path, uint32_t data_addr) {
  if (data_addr < dir_entry_sec.virtual_address) {
    throw invalid_data_addr{
        "Address of payload data < "
        "OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress."};
  }

  const auto payload_end_addr =
      dir_entry_sec.virtual_address + dir_entry_sec.size;
  if (payload_end_addr < data_addr) {
    throw invalid_data_addr{
        "Address of payload data > "
        "address of the end of the section "
        "from OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress"};
  }

  file_utils::resize_file(file_path, data_addr);

  const uint32_t size = data_addr - dir_entry_sec.virtual_address;
  fs.seekg(dir_entry_sec_size_addr);
  fs.write(reinterpret_cast<const char*>(&size), sizeof(size));
}

inline uint32_t write_payload(std::fstream& fs, const payload& payload,
                              const image_data_directory& dir_entry_sec,
                              uint32_t dir_entry_sec_size_addr) {
  const auto data_addr = dir_entry_sec.virtual_address + dir_entry_sec.size;

  fs.seekg(data_addr);
  fs.write(payload.get_data(), payload.get_data_size());

  const auto res = fs.tellg() % pe::padding;
  const auto number_of_align_bytes = res ? pe::padding - res : res;

  for (int i = 0; i < number_of_align_bytes; ++i) {
    fs.put('\0');
  }

  fs.seekg(dir_entry_sec_size_addr);
  const auto size = static_cast<uint32_t>(
      payload.get_data_size() + dir_entry_sec.size + number_of_align_bytes);
  fs.write(reinterpret_cast<const char*>(&size), sizeof(size));

  return data_addr;
}

inline buf_type read_payload(std::istream& stream,
                             const image_data_directory& dir_entry_sec,
                             uint32_t data_addr, uint32_t data_size) {
  if (data_addr < dir_entry_sec.virtual_address) {
    throw invalid_data_addr{
        "Address of payload data < "
        "OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress."};
  }

  const auto payload_end_addr =
      dir_entry_sec.virtual_address + dir_entry_sec.size;
  if (payload_end_addr < data_addr) {
    throw invalid_data_addr{
        "Address of payload data > "
        "address of the end of the section "
        "from OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress"};
  }

  if (data_addr + data_size > payload_end_addr) {
    throw invalid_data_addr{
        "Address of payload data + size > "
        "address of the end of the section "
        "from OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress"};
  }

  const auto size = data_size == 0 ? payload_end_addr - data_addr : data_size;
  buf_type buf(size);
  return file_utils::read<char>(stream, data_addr, buf);
}

}  // namespace payload
}  // namespace detail
}  // namespace wdpe