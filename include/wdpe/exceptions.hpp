/**
 * @file exceptions.hpp
 */

#pragma once

#include <stdexcept>
#include <string>

namespace wdpe {

/**
 * Base class of wdpe library exceptions.
 */
class wdpe_error : public std::runtime_error {
 public:
  wdpe_error(const std::string& message) : std::runtime_error(message) {}
};

/**
 * Thrown when the injected data is corrupted.
 */
class payload_corrupted : public wdpe_error {
 public:
  payload_corrupted(const std::string& message) : wdpe_error(message) {}
};

/**
 * Thrown when the file format is unknown.
 */
class unknown_file_format : public wdpe_error {
 public:
  unknown_file_format(const std::string& message) : wdpe_error(message) {}
};

/**
 * Thrown when the injected data address is invalid.
 */
class invalid_data_addr : public wdpe_error {
 public:
  invalid_data_addr(const std::string& message) : wdpe_error(message) {}
};

/**
 * Thrown when the file is not signed.
 */
class auth_signature_not_found : public wdpe_error {
 public:
  auth_signature_not_found(const std::string& message) : wdpe_error(message) {}
};

}  // namespace wdpe