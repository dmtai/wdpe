/**
 * @file wdpe_payload.hpp
 */

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <wdpe/detail/crypto/checksum.hpp>
#include <wdpe/detail/pe/pe_parser.hpp>
#include <wdpe/detail/utils/file_utils.hpp>
#include <wdpe/exceptions.hpp>

namespace wdpe {
namespace detail {
namespace wdpe_payload {

using buf_type = std::vector<char>;

// Signature of wdpe payload format.
using signature_type = std::array<uint8_t, 4>;
constexpr signature_type signature{0x90, 0x83, 0x97, 0x82};

// Offsets of wdpe format data blocks from wdpe signature address.
constexpr uint32_t payload_data_addr_offset{sizeof(uint32_t)};
constexpr uint32_t payload_data_size_offset{payload_data_addr_offset +
                                            sizeof(uint32_t)};
constexpr uint32_t payload_data_checksum_offset{payload_data_size_offset +
                                                sizeof(uint32_t)};

class payload {
 public:
  payload(const char* data, uint32_t size, uint32_t address) noexcept
      : data_{data},
        data_size_{size},
        address_{address},
        checksum_{crypto::calculate_checksum(data, size)},
        size_{static_cast<uint32_t>(data_size_ + sizeof(data_size_) +
                                    sizeof(address_) + sizeof(checksum_) +
                                    signature.size())} {}

  const char* get_data() const noexcept { return data_; }

  const uint32_t& get_data_size() const noexcept { return data_size_; }

  const uint32_t& get_size() const noexcept { return size_; }

  const uint32_t& get_checksum() const noexcept { return checksum_; }

  const uint32_t& get_address() const noexcept { return address_; }

  const signature_type& get_signature() const noexcept { return signature; }

 private:
  const char* data_;
  const uint32_t data_size_;
  const uint32_t address_;
  const uint32_t checksum_;
  const uint32_t size_;
};

inline void write_wdpe_payload(std::fstream& fs, const payload& payload,
                               const image_data_directory& dir_entry_sec,
                               uint32_t sec_dir_size_addr) {
  fs.seekg(payload.get_address());
  fs.write(payload.get_data(), payload.get_data_size());
  fs.write(reinterpret_cast<const char*>(&payload.get_checksum()),
           sizeof(uint32_t));
  fs.write(reinterpret_cast<const char*>(&payload.get_data_size()),
           sizeof(uint32_t));
  fs.write(reinterpret_cast<const char*>(&payload.get_address()),
           sizeof(uint32_t));
  const auto& signature = payload.get_signature();
  fs.write(reinterpret_cast<const char*>(signature.data()), signature.size());

  const auto res = fs.tellg() % pe::padding;
  const auto number_of_align_bytes = res ? pe::padding - res : res;

  for (int i = 0; i < number_of_align_bytes; ++i) {
    fs.put('\0');
  }

  fs.seekg(sec_dir_size_addr);
  const auto size = static_cast<uint32_t>(
      payload.get_size() + dir_entry_sec.size + number_of_align_bytes);
  fs.write(reinterpret_cast<const char*>(&size), sizeof(size));
}

class payload_parser {
 public:
  payload_parser(std::istream& stream,
                 const image_data_directory& dir_entry_sec,
                 uint32_t sign_offset)
      : stream_{stream},
        dir_entry_sec_{dir_entry_sec},
        signature_addr_{dir_entry_sec_.virtual_address + dir_entry_sec_.size -
                        sign_offset} {}

  static bool find_wdpe_signature_offset(
      std::istream& stream, const image_data_directory& dir_entry_sec,
      uint32_t& sign_offset) {
    const auto payload_end_offset =
        dir_entry_sec.virtual_address + dir_entry_sec.size;

    bool is_sign_found{false};
    uint32_t offset{1};

    const auto sig_size = static_cast<int>(signature.size());
    const auto sig_end_idx = sig_size - 1;
    for (int sig_idx = sig_end_idx; offset < pe::padding + sig_size; ++offset) {
      const auto buf =
          file_utils::read<uint8_t>(stream, payload_end_offset - offset);
      if (buf == signature[sig_idx]) {
        if (sig_idx == 0) {
          is_sign_found = true;
          break;
        } else {
          --sig_idx;
        }
      } else {
        sig_idx = sig_end_idx;
      }
    }

    if (!is_sign_found) {
      return false;
    }

    sign_offset = offset;
    return true;
  }

  uint32_t read_data_addr() {
    return file_utils::read<uint32_t>(
        stream_, signature_addr_ - payload_data_addr_offset);
  }

  uint32_t read_data_size() {
    return file_utils::read<uint32_t>(
        stream_, signature_addr_ - payload_data_size_offset);
  }

  uint32_t read_data_checksum() {
    return file_utils::read<uint32_t>(
        stream_, signature_addr_ - payload_data_checksum_offset);
  }

  buf_type read_data() {
    const auto data_addr = read_data_addr();
    if (data_addr < dir_entry_sec_.virtual_address) {
      throw payload_corrupted{
          "wdpe payload address less than "
          "OptionalHeader.DataDirectory"
          "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress."};
    }

    const auto payload_end_addr =
        dir_entry_sec_.virtual_address + dir_entry_sec_.size;
    if (payload_end_addr < data_addr) {
      throw payload_corrupted{
          "wdpe payload address more than "
          "address of the end of the section "
          "from OptionalHeader.DataDirectory"
          "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress"};
    }

    const auto data_size = read_data_size();
    if (dir_entry_sec_.size < data_size) {
      throw payload_corrupted{
          "wdpe payload size more than "
          "OptionalHeader.DataDirectory"
          "[IMAGE_DIRECTORY_ENTRY_SECURITY].Size."};
    }

    buf_type buf(data_size);
    return file_utils::read<char>(stream_, data_addr, buf);
  }

 private:
  std::istream& stream_;
  const image_data_directory& dir_entry_sec_;
  const uint32_t signature_addr_;
};

inline buf_type read_wdpe_payload(std::istream& stream,
                                  const image_data_directory& dir_entry_sec) {
  uint32_t sign_offset;
  if (!payload_parser::find_wdpe_signature_offset(stream, dir_entry_sec,
                                                  sign_offset)) {
    return {};
  }
  payload_parser parser{stream, dir_entry_sec, sign_offset};
  const auto data = parser.read_data();
  const auto checksum = parser.read_data_checksum();

  if (!crypto::verify_checksum(data, checksum)) {
    throw payload_corrupted{
        "Checksum verification of payload in wdpe format failed."};
  }
  return data;
}

inline bool is_wdpe_payload_present(std::istream& stream,
                                    const image_data_directory& dir_entry_sec) {
  uint32_t sign_offset;
  return payload_parser::find_wdpe_signature_offset(stream, dir_entry_sec,
                                                    sign_offset);
}

inline void delete_payload(std::fstream& fs,
                           const image_data_directory& dir_entry_sec,
                           uint32_t dir_entry_sec_size_addr,
                           const std::string& file_path) {
  uint32_t sign_offset;
  if (!payload_parser::find_wdpe_signature_offset(fs, dir_entry_sec,
                                                  sign_offset)) {
    // wdpe signature not found in the file. Nothing to delete.
    return;
  }
  payload_parser parser{fs, dir_entry_sec, sign_offset};
  const auto data_addr = parser.read_data_addr();

  if (data_addr < dir_entry_sec.virtual_address) {
    throw payload_corrupted{
        "wdpe payload address less than "
        "OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress."};
  }

  const auto payload_end_addr =
      dir_entry_sec.virtual_address + dir_entry_sec.size;
  if (payload_end_addr < data_addr) {
    throw payload_corrupted{
        "wdpe payload size more than "
        "OptionalHeader.DataDirectory"
        "[IMAGE_DIRECTORY_ENTRY_SECURITY].Size."};
  }

  file_utils::resize_file(file_path, data_addr);

  const uint32_t size = data_addr - dir_entry_sec.virtual_address;
  fs.seekg(dir_entry_sec_size_addr);
  fs.write(reinterpret_cast<const char*>(&size), sizeof(size));
}

}  // namespace wdpe_payload
}  // namespace detail
}  // namespace wdpe