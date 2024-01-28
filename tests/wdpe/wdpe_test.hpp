/**
 * @file wdpe_test.hpp
 */

#include <string>
#include "gtest/gtest.h"

namespace wdpe {

class TestEnvironment : public ::testing::Environment {
 public:
  explicit TestEnvironment(const std::string& pe_files,
                           const std::string& not_pe_file,
                           const std::string& unsigned_sign_file);
};

}  // namespace wdpe