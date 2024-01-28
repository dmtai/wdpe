/**
 * @file pe.hpp
 */

#pragma once

#include <cstdint>

namespace wdpe {

/// IMAGE_DATA_DIRECTORY PE-file structure.
struct image_data_directory {
  uint32_t virtual_address;
  uint32_t size;
};

}  // namespace wdpe