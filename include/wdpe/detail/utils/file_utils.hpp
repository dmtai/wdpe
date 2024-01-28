/**
 * @file file_utils.hpp
 */

#pragma once

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#if (__cplusplus >= 201703L)
#include <filesystem>
#elif defined(_WIN32)
#include <Windows.h>
#else
#include <unistd.h>
#endif

namespace wdpe {
namespace detail {
namespace file_utils {

#if (__cplusplus >= 201703L)

inline void resize_file_impl(const char* p, uintmax_t size) {
  std::filesystem::resize_file(p, size);
}

#elif defined(_WIN32)

inline void resize_file_impl(const char* p, uintmax_t size) {
  const auto file_handle = CreateFile(
      p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file_handle == INVALID_HANDLE_VALUE) {
    throw std::system_error{static_cast<int>(GetLastError()),
                            std::system_category()};
  }
  const std::unique_ptr<std::remove_pointer<HANDLE>::type,
                        decltype(&CloseHandle)>
      on_exit(file_handle, &CloseHandle);

  LARGE_INTEGER sz;
  sz.QuadPart = size;
  if (!SetFilePointerEx(file_handle, sz, 0, FILE_BEGIN)) {
    throw std::system_error{static_cast<int>(GetLastError()),
                            std::system_category()};
  }

  if (!SetEndOfFile(file_handle)) {
    throw std::system_error{static_cast<int>(GetLastError()),
                            std::system_category()};
  }
}

#else

inline void resize_file_impl(const char* p, uintmax_t size) {
  if (::truncate(p, size) != 0) {
    throw std::system_error{errno, std::system_category()};
  }
}

#endif

inline void resize_file(const std::string& file_path, std::uintmax_t size) {
  resize_file_impl(file_path.c_str(), size);
}

inline std::streamoff get_file_size(std::istream& file) {
  std::streamoff old_offset = file.tellg();
  file.seekg(0, std::ios::end);
  std::streamoff file_size = file.tellg();
  file.seekg(old_offset);
  return file_size;
}

template <typename T>
std::vector<T>& read(std::istream& ifs, std::istream::pos_type offset,
                     std::vector<T>& buf) {
  static_assert(std::is_trivial<T>::value, "T must be a trivial type");
  ifs.seekg(offset).read(reinterpret_cast<char*>(buf.data()),
                         static_cast<std::streamsize>(sizeof(T) * buf.size()));
  return buf;
}

template <typename T>
T read(std::istream& ifs, std::istream::pos_type offset) {
  static_assert(std::is_trivial<T>::value, "T must be a trivial type");
  T buf;
  ifs.seekg(offset).read(reinterpret_cast<char*>(&buf),
                         static_cast<std::streamsize>(sizeof(T)));
  return buf;
}

}  // namespace file_utils
}  // namespace detail
}  // namespace wdpe