/**
 * @file wdpe.hpp
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <wdpe/common.hpp>
#include <wdpe/exceptions.hpp>
#include <wdpe/pe.hpp>

namespace wdpe {

/**
 * Delete data(previously written in the wdpe library format using wdpe::write)
 * without invalidating the authenticode digital signature. Updates the checksum
 * of the file.
 * @param file_path supplies path to the file with data.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format or data
 *        stored at the security directory file offset not at the end of the
 *        file.
 * @throw wdpe::payload_corrupted if the payload is corrupted and its
          address cannot be determined.
 * @throw std::system_error if an error occurs when calling the system function
 *        to delete data from the file.
 */
WDPE_API void delete_payload(const std::string& file_path);

/**
 * Packages data into wdpe library format and writes it to the file without
 * invalidating the authenticode digital signature. Updates the checksum of the
 * file. If data was previously written, overwrites it.
 * @param file_path supplies path to the file to write data.
 * @param data supplies pointer to data to write.
 * @param size supplies size of written data.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format or data
 *        stored at the security directory file offset not at the end of the
 *        file.
 * @throw wdpe::payload_corrupted if, when overwriting a previously written
 *        payload, it is discovered that it is corrupted and cannot be
 *        overwritten correctly.
 * @throw wdpe::auth_signature_not_found if the file isn't signed.
 * @throw std::system_error if an error occurs when calling the system function
 *        to delete data from the file when overwriting.
 */
WDPE_API void write(const std::string& file_path, const char* data,
                    uint32_t size);

/**
 * Reads data previously written in the wdpe library format using wdpe::write.
 * Checks the checksum of read data. If the data was damaged, an exception is
 * thrown.
 * @param file_path supplies path to the file with data.
 * @return std::vector<char> with the read data. If there is no data, an empty
 *         vector will be returned.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format.
 * @throw wdpe::payload_corrupted if the payload is corrupted.
 */
WDPE_API std::vector<char> read(const std::string& file_path);

/**
 * Checks if the file contains injected data in wdpe format.
 * @param file_path supplies path to the file with data.
 * @return true if wdpe payload is present, false otherwise.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format.
 */
WDPE_API bool is_payload_present(const std::string& file_path);

/**
 * Delete data(previously written using wdpe::write_raw_data) without
 * invalidating the authenticode digital signature. Updates the checksum of the
 * file.
 * @param file_path supplies path to the file with data.
 * @param data_addr supplies address of the data in the file returned by
 *                  wdpe::write_raw_data.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format or data
 *        stored at the security directory file offset not at the end of the
 *        file.
 * @throw wdpe::invalid_data_addr if address of the data in the file is invalid.
 * @throw std::system_error if an error occurs when calling the system function
 *        to delete data from the file.
 */
WDPE_API void delete_raw_data(const std::string& file_path, uint32_t data_addr);

/**
 * Writes data to the file without invalidating the authenticode digital
 * signature. Updates the checksum of the file. Adds alignment in multiples
 * of 8. If data has already been written, the new data will be written to the
 * end of the section with it(after zero alignment bytes).
 * @param file_path supplies path to the file to write data.
 * @param data supplies pointer to data to write.
 * @param size supplies size of written data.
 * @return uint32_t with address of written data in the file.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format or data
 *        stored at the security directory file offset not at the end of the
 *        file.
 * @throw wdpe::auth_signature_not_found if the file isn't signed.
 */
WDPE_API uint32_t write_raw_data(const std::string& file_path, const char* data,
                                 uint32_t size);

/**
 * Reads data previously written using wdpe::write_raw_data.
 * @param file_path supplies path to the file with data.
 * @param data_addr supplies address of the data in the file.
 * @param size supplies size of the data in bytes. If size == 0, the written
 *             data will be read starting at the passed address, including zero
 *             alignment bytes.
 * @return std::vector<char> with the read data.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format.
 * @throw wdpe::invalid_data_addr if address of the data in the file is invalid.
 */
WDPE_API std::vector<char> read_raw_data(const std::string& file_path,
                                         uint32_t data_addr, uint32_t size = 0);

/**
 * Reads OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]. The data
 * injected by the wdpe library is located at the end of this section. Can be
 * useful for reading injected data from the end of the section by address
 * wdpe::pe::image_data_directory.virtual_address.
 * @param file_path supplies path to the file.
 * @return wdpe::pe::image_data_directory with virtual_address that contains the
 * address of the section with digital signature data and data injected by the
 * library and size of this section.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format.
 */
WDPE_API image_data_directory
read_image_dir_entry_security(const std::string& file_path);

/**
 * Delete the authenticode digital signature of the file. The injected
 * data will also be deleted. If there is no signature, it does nothing.
 * @param file_path supplies path to the signed file.
 * @throw std::ios_base::failure if there is a problem opening/writing/reading
 *        the file.
 * @throw wdpe::unknown_file_format if the file isn't in PE format or data
 *        stored at the security directory file offset not at the end of the
 * file.
 */
WDPE_API void delete_auth_signature(const std::string& file_path);

}  // namespace wdpe