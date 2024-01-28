#include <filesystem>
#include <iostream>
#include <string>
#include "gtest/gtest.h"
#include "wdpe/wdpe_test.hpp"

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  testing::AddGlobalTestEnvironment(
      new wdpe::TestEnvironment(argv[1], argv[2], argv[3]));
  return RUN_ALL_TESTS();
}