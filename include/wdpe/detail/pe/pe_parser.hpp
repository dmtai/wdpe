/**
 * @file pe_parser.hpp
 */

#pragma once

#include <fstream>
#include <string>
#include <wdpe/detail/utils/file_utils.hpp>
#include <wdpe/exceptions.hpp>
#include <wdpe/pe.hpp>

namespace wdpe {
namespace detail {
namespace pe {

// Address of IMAGE_DOS_HEADER.e_lfanew.
constexpr uint32_t e_lfanew_address{60};
// 'MZ' signature.
constexpr uint16_t dos_signature{0x5A4D};
// Size of IMAGE_NT_HEADERS.Signature.
constexpr uint16_t nt_signature_size{sizeof(uint32_t)};

// Offset of DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] in
// IMAGE_OPTIONAL_HEADER32.
constexpr uint32_t x86_offsetof_sec_dir_in_opt_hdr{128};
// Offset of DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] in
// IMAGE_OPTIONAL_HEADER64.
constexpr uint32_t x64_offsetof_sec_dir_in_opt_hdr{144};
// Offset of OptionalHeader in IMAGE_NT_HEADERS.
constexpr uint32_t offsetof_opt_hdr_in_nt_hdr{24};

// Offset of Size in IMAGE_DATA_DIRECTORY.
constexpr uint32_t offsetof_data_dir_size{4};
// Size of Size in IMAGE_DATA_DIRECTORY.
constexpr uint32_t sizeof_data_dir_size{4};

// Size of IMAGE_FILE_HEADER
constexpr uint32_t image_file_header_size{20};
// Checksum offset in IMAGE_OPTIONAL_HEADER
constexpr uint32_t checksum_offset_in_opt_header{64};
// Size of signature in IMAGE_OPTIONAL_HEADER
constexpr uint32_t opt_header_signature_size{4};
// Offset of IMAGE_OPTIONAL_HEADER.Checksum from the beginning of
// IMAGE_NT_HEADER
constexpr uint32_t checksum_offset_in_nt_header{opt_header_signature_size +
                                                image_file_header_size +
                                                checksum_offset_in_opt_header};

// Size of IMAGE_OPTIONAL_HEADER.Checksum in IMAGE_OPTIONAL_HEADER
constexpr uint32_t opt_header_checksum_size{4};

const uint32_t padding{8};

// IMAGE_FILE_HEADER.Machine types.
enum class machine : uint16_t {
  image_file_machine_i386 = 0x014c,
  image_file_machine_amd64 = 0x8664
};

class pe_parser {
 public:
  enum class arch_type { unknown, x64, x86 };

  pe_parser(std::istream& stream) : stream_{stream} {
    if (read_dh_e_magic() != dos_signature) {
      throw unknown_file_format(
          "The file isn't in PE format. "
          "Invalid IMAGE_DOS_HEADER signature.");
    }
    nt_offset_ = read_dh_e_lfanew();

    const auto fh_machine = read_fh_machine();
    switch (fh_machine) {
      default:
        throw unknown_file_format("Unknown architecture type of the file.");
      case static_cast<uint16_t>(machine::image_file_machine_i386):
        arch_type_ = arch_type::x86;
        break;
      case static_cast<uint16_t>(machine::image_file_machine_amd64):
        arch_type_ = arch_type::x64;
        break;
    }
  }

  uint16_t read_dh_e_magic() { return file_utils::read<uint16_t>(stream_, 0); }

  uint32_t read_dh_e_lfanew() {
    return file_utils::read<uint32_t>(stream_, e_lfanew_address);
  }

  uint16_t read_fh_machine() {
    return file_utils::read<uint16_t>(stream_, nt_offset_ + nt_signature_size);
  }

  image_data_directory read_image_dir_entry_security() {
    return file_utils::read<image_data_directory>(
        stream_, get_image_dir_entry_security_addr());
  }

  uint32_t get_image_dir_entry_security_size_addr() const noexcept {
    return get_image_dir_entry_security_addr() + offsetof_data_dir_size;
  }

  uint32_t get_image_dir_entry_security_addr() const noexcept {
    const uint32_t addr = nt_offset_ + offsetof_opt_hdr_in_nt_hdr;
    if (arch_type_ == arch_type::x64) {
      return addr + x64_offsetof_sec_dir_in_opt_hdr;
    }
    return addr + x86_offsetof_sec_dir_in_opt_hdr;
  }

  uint32_t get_checksum_addr() const noexcept {
    return nt_offset_ + checksum_offset_in_nt_header;
  }

  uint32_t get_checksum_size() const noexcept {
    return opt_header_checksum_size;
  }

 private:
  std::istream& stream_;
  uint32_t nt_offset_;
  arch_type arch_type_;
};

}  // namespace pe
}  // namespace detail
}  // namespace wdpe