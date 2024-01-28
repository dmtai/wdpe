/**
 * @file wdpe.hpp
 */

#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <wdpe/common.hpp>
#include <wdpe/detail/auth_signature/auth_signature.hpp>
#include <wdpe/detail/crypto/checksum.hpp>
#include <wdpe/detail/payload/payload.hpp>
#include <wdpe/detail/payload/wdpe_payload.hpp>
#include <wdpe/detail/pe/pe_parser.hpp>
#include <wdpe/detail/pe/utils.hpp>
#include <wdpe/detail/utils/file_utils.hpp>
#include <wdpe/pe.hpp>
#include <wdpe/wdpe.hpp>

namespace wdpe {

WDPE_INLINE void delete_payload(const std::string& file_path) {
  using namespace detail;

  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    return;
  }

  pe::validate_section_position(data_dir, file_utils::get_file_size(fs));

  wdpe_payload::delete_payload(
      fs, data_dir, parser.get_image_dir_entry_security_size_addr(), file_path);
  crypto::update_file_checksum(fs, parser.get_checksum_addr());
}

WDPE_INLINE void write(const std::string& file_path, const char* data,
                       uint32_t size) {
  using namespace detail;

  if (size == 0) {
    return;
  }

  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    throw auth_signature_not_found{
        "Authenticode digital signature not found in the file."};
  }

  pe::validate_section_position(data_dir, file_utils::get_file_size(fs));

  const auto size_addr = parser.get_image_dir_entry_security_size_addr();
  wdpe_payload::delete_payload(fs, data_dir, size_addr, file_path);

  wdpe_payload::payload payload{data, size,
                                data_dir.virtual_address + data_dir.size};
  wdpe_payload::write_wdpe_payload(fs, payload, data_dir, size_addr);
  crypto::update_file_checksum(fs, parser.get_checksum_addr());
}

WDPE_INLINE std::vector<char> read(const std::string& file_path) {
  using namespace detail;

  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    return {};
  }

  return wdpe_payload::read_wdpe_payload(fs, data_dir);
}

WDPE_INLINE bool is_payload_present(const std::string& file_path) {
  using namespace detail;

  std::ifstream fs;
  fs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
  fs.open(file_path, std::ifstream::binary | std::ifstream::in);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    return false;
  }

  return wdpe_payload::is_wdpe_payload_present(fs, data_dir);
}

WDPE_INLINE void delete_raw_data(const std::string& file_path,
                                 uint32_t data_addr) {
  using namespace detail;

  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    return;
  }

  pe::validate_section_position(data_dir, file_utils::get_file_size(fs));

  payload::delete_payload(fs, data_dir,
                          parser.get_image_dir_entry_security_size_addr(),
                          file_path, data_addr);
  crypto::update_file_checksum(fs, parser.get_checksum_addr());
}

WDPE_INLINE uint32_t write_raw_data(const std::string& file_path,
                                    const char* data, uint32_t size) {
  using namespace detail;

  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    throw auth_signature_not_found{
        "Authenticode digital signature not found in the file."};
  }

  pe::validate_section_position(data_dir, file_utils::get_file_size(fs));

  payload::payload payload{data, size};
  const auto data_addr = payload::write_payload(
      fs, payload, data_dir, parser.get_image_dir_entry_security_size_addr());
  crypto::update_file_checksum(fs, parser.get_checksum_addr());

  return data_addr;
}

WDPE_INLINE std::vector<char> read_raw_data(const std::string& file_path,
                                            uint32_t data_addr, uint32_t size) {
  using namespace detail;

  std::ifstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path, std::fstream::binary | std::fstream::in);

  pe::pe_parser parser{fs};
  const auto data_dir = parser.read_image_dir_entry_security();
  if (pe::is_empty(data_dir)) {
    return {};
  }

  return payload::read_payload(fs, data_dir, data_addr, size);
}

WDPE_INLINE image_data_directory
read_image_dir_entry_security(const std::string& file_path) {
  using namespace detail;

  std::ifstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path, std::fstream::binary | std::fstream::in);

  pe::pe_parser parser{fs};
  return parser.read_image_dir_entry_security();
}

WDPE_INLINE void delete_auth_signature(const std::string& file_path) {
  using namespace detail;

  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  pe::pe_parser parser{fs};

  const auto data_dir = parser.read_image_dir_entry_security();
  if (!data_dir.virtual_address) {
    return;
  }

  pe::validate_section_position(data_dir, file_utils::get_file_size(fs));

  auth_signature::delete_signature(
      fs, data_dir, parser.get_image_dir_entry_security_addr(), file_path);
  crypto::update_file_checksum(fs, parser.get_checksum_addr());
}

}  // namespace wdpe