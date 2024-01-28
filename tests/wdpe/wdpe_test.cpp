/**
 * @file wdpe_test.cpp
 */

#include "wdpe_test.hpp"
#include <LIEF/PE.hpp>
#include <filesystem>
#include <iostream>
#include <string>
#include "gtest/gtest.h"
#include "wdpe/wdpe_inl.hpp"

namespace wdpe {

namespace {

std::string pe_files_for_tests_path;
std::string not_pe_file_path;
std::string unsigned_file_path;
constexpr std::string_view pe_files_tmp_dir_path{"./pe_files_tmp_dir"};
constexpr std::string_view not_pe_file_tmp_dir_path{"./not_pe_file_tmp_dir"};
constexpr std::string_view unsigned_file_tmp_dir_path{
    "./unsigned_file_tmp_dir"};

bool verify_signature(const std::string& file_path) {
  const auto binary = LIEF::PE::Parser::parse(file_path);
  return binary->verify_signature() ==
         LIEF::PE::Signature::VERIFICATION_FLAGS::OK;
}

bool update_wdpe_addr(const std::string& file_path, uint32_t fake_addr) {
  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  wdpe::detail::pe::pe_parser parser{fs};
  const auto dir_entry_sec = parser.read_image_dir_entry_security();
  uint32_t sign_offset;
  if (!wdpe::detail::wdpe_payload::payload_parser::find_wdpe_signature_offset(
          fs, dir_entry_sec, sign_offset)) {
    return false;
  }

  const auto data_addr =
      dir_entry_sec.virtual_address + dir_entry_sec.size - sign_offset - 4;

  fs.seekg(data_addr);
  fs.write(reinterpret_cast<char*>(&fake_addr), sizeof(fake_addr));
  return true;
}

bool update_wdpe_data(const std::string& file_path, uint32_t fake_data) {
  std::fstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path,
          std::fstream::binary | std::fstream::in | std::fstream::out);

  wdpe::detail::pe::pe_parser parser{fs};
  const auto dir_entry_sec = parser.read_image_dir_entry_security();
  uint32_t sign_offset;
  if (!wdpe::detail::wdpe_payload::payload_parser::find_wdpe_signature_offset(
          fs, dir_entry_sec, sign_offset)) {
    return false;
  }

  wdpe::detail::wdpe_payload::payload_parser payload_parser{fs, dir_entry_sec,
                                                            sign_offset};

  const auto data_addr = payload_parser.read_data_addr();

  fs.seekg(data_addr);
  fs.write(reinterpret_cast<char*>(&fake_data), sizeof(fake_data));
  return true;
}

image_data_directory get_image_dir_entry_security(
    const std::string& file_path) {
  std::ifstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path, std::fstream::binary | std::fstream::in);

  uint32_t nt_offset;
  fs.seekg(60);
  fs.read(reinterpret_cast<char*>(&nt_offset), sizeof(nt_offset));

  uint16_t fh_machine;
  fs.seekg(nt_offset + sizeof(uint32_t));
  fs.read(reinterpret_cast<char*>(&fh_machine), sizeof(fh_machine));

  uint32_t addr = nt_offset + 24;
  switch (fh_machine) {
    default:
      throw std::runtime_error("Unknown architecture type of the file.");
    case static_cast<uint16_t>(0x014c):
      addr += 128;
      break;
    case static_cast<uint16_t>(0x8664):
      addr += 144;
      break;
  }

  wdpe::image_data_directory data_dir;
  fs.seekg(addr);
  fs.read(reinterpret_cast<char*>(&data_dir), sizeof(data_dir));
  return data_dir;
}

class WdpeTest : public testing::Test {
 protected:
  void SetUp() override {
    std::filesystem::remove_all(pe_files_tmp_dir_path);
    std::filesystem::remove_all(not_pe_file_tmp_dir_path);
    std::filesystem::remove_all(unsigned_file_tmp_dir_path);

    std::filesystem::copy(pe_files_for_tests_path, pe_files_tmp_dir_path);
    std::filesystem::copy(not_pe_file_path, not_pe_file_tmp_dir_path);
    std::filesystem::copy(unsigned_file_path, unsigned_file_tmp_dir_path);

    std::filesystem::directory_iterator it1{not_pe_file_tmp_dir_path};
    not_pe_file_path_ = it1->path().string();

    std::filesystem::directory_iterator it2{unsigned_file_tmp_dir_path};
    unsigned_file_path_ = it2->path().string();

    dir_iterator_ = std::filesystem::directory_iterator{pe_files_tmp_dir_path};

    test_data_ = std::vector<std::string>{
        "",
        "a",
        "aB",
        "a2c",
        "awcd",
        "abAde",
        "fesres",
        "gjiregf",
        "bbvjffdi",
        "kjh34sdvx",
        "bvcbfgfdKd",
        "vcxv834kvxd",
        "4324ikjvicjx",
        "jiufiIaiSADAA",
        "AAAAAAAADSDAAA",
        "fgdgfdgfdgdfooo",
        "1231234324899655",
        "sdfbAaew3waewfdss",
    };

    test_text_ =
        "<p>Lorem ipsum dolor sit amet. Est autem molestias qui veritatis "
        "omnis non deleniti animi At tempora quas est galisum dolores. Ea unde "
        "voluptatibus qui obcaecati totam a aperiam voluptate in quod "
        "reprehenderit quo dolorem impedit? </p><p>Sit quia voluptate qui "
        "laboriosam doloribus rem nisi nulla cum consequatur accusantium At "
        "repudiandae quam. Ut inventore quam ut perferendis reiciendis aut "
        "galisum corrupti ut temporibus vero non facere iusto. Et rerum "
        "mollitia a corrupti aliquam aut vitae odio eum omnis iure qui "
        "blanditiis velit aut ducimus consequatur. </p><p>Aut magnam "
        "laudantium sit ullam sunt et soluta enim sit sequi voluptatibus 33 "
        "beatae iure. Eos nostrum rerum nam maiores consequatur et enim "
        "nostrum eos tempora neque est assumenda praesentium. </p><p>Ea iste "
        "repellendus eos doloribus eius est libero voluptatem ut suscipit "
        "voluptate sed quas sapiente est nostrum vero! Id inventore laboriosam "
        "est sapiente sunt non inventore dolorem aut nostrum error in "
        "reiciendis autem qui voluptas illo. </p><p>Sit distinctio minima qui "
        "dolorem totam ut enim corrupti in adipisci voluptate qui itaque "
        "saepe. A iusto quia ut voluptate rerum et ducimus amet a aliquam "
        "possimus aut cupiditate voluptate et odit itaque est doloribus "
        "galisum! </p><p>Aut enim recusandae hic deserunt beatae 33 aliquam "
        "amet qui reiciendis similique aut quod iure qui dicta dicta. Sed "
        "sequi voluptatum aut quia optio cum animi mollitia id beatae "
        "blanditiis. Ea autem corrupti et praesentium rerum in animi quae et "
        "mollitia nesciunt hic adipisci quaerat et dolorem quibusdam et "
        "tempora sint? </p><p>Ut laboriosam consectetur id molestiae odio sed "
        "sunt fuga. Et quam consequuntur qui maxime dolorum ut cupiditate "
        "voluptatem non nisi omnis ea consequatur animi. Sed dolorum optio sit "
        "praesentium magnam aut rerum nobis qui magni iure et ullam "
        "consequatur. </p><p>Vel perspiciatis deleniti est voluptatem soluta "
        "est reiciendis amet aut vero magni et sunt dolores ad voluptatum "
        "harum. In sint libero ut voluptatem commodi eos distinctio corporis "
        "aut voluptas possimus et exercitationem esse. Sed fugiat voluptatibus "
        "id necessitatibus consequatur et fugit nulla a laborum laudantium. "
        "</p><p>Ab neque quam id sequi culpa et nihil eligendi ut Quis omnis "
        "aut provident provident aut beatae architecto. Eum cumque voluptatem "
        "et quaerat deleniti a sint dolor quo magnam natus eum minus "
        "doloremque? Ea quae officiis qui voluptatibus dolor sit debitis "
        "consequatur qui adipisci numquam non quasi pariatur. Qui fuga fugiat "
        "At modi incidunt qui rerum culpa. </p><p>Et pariatur omnis est "
        "accusantium nihil ut quidem repellendus id inventore voluptas sit "
        "officia nesciunt qui soluta nisi qui possimus error. Aut recusandae "
        "quaerat aut distinctio omnis ut vero eveniet eos sint repudiandae et "
        "temporibus Quis rem quibusdam quia? </p><p>Aut quod laudantium nam "
        "optio eaque et illo voluptatum hic temporibus voluptate et deleniti "
        "debitis aut cupiditate perferendis et quia tempore. Et nisi omnis quo "
        "unde beatae et corrupti sint sed labore harum qui internos "
        "consequatur sit sunt galisum. Est similique excepturi quo ratione "
        "labore est internos magnam est possimus quibusdam est numquam odio "
        "aut laboriosam quia vel dolores adipisci. </p><p>Et aspernatur minima "
        "ut reprehenderit fugiat ad voluptatibus expedita et fugiat odio quo "
        "voluptas commodi qui maxime odit est facilis fuga. Id numquam aperiam "
        "qui nihil internos quo asperiores unde ea temporibus dolor. Id "
        "aliquam dicta qui ullam veniam ad molestiae aliquam ea galisum "
        "tenetur et quia dicta ea asperiores dolores? Et quasi doloribus eum "
        "omnis laudantium qui corrupti pariatur vel impedit quod? </p><p>Qui "
        "modi minus ex incidunt voluptatem in officiis dolorum est reiciendis "
        "consequatur est molestias aspernatur eos voluptatem dolorem. Sed "
        "distinctio corporis est expedita voluptas 33 repudiandae voluptatum "
        "ea iste dolores. </p><p>Et molestiae suscipit aut assumenda sint ut "
        "consequuntur deserunt. Ea doloribus sunt eum soluta iure et animi "
        "facilis et minus velit aut commodi ipsa qui distinctio reprehenderit. "
        "</p><p>Ex vitae minima est dolor temporibus est quaerat quasi quo "
        "consequatur enim sit explicabo accusamus a deserunt maiores eum sint "
        "quisquam. Id natus voluptas est molestiae excepturi sit fugiat "
        "aperiam quo incidunt quam. Rem nemo ullam sit officiis voluptas sed "
        "omnis provident. </p><p>Est dicta architecto aut itaque voluptas et "
        "ratione quam et dolor voluptas sed sunt omnis eum debitis porro qui "
        "illo rerum. In consequuntur consectetur ut consectetur libero et "
        "consequatur quia aut quos consequuntur aut aperiam voluptatem? Vel "
        "praesentium expedita quo internos enim non numquam voluptatem et "
        "doloremque tempora sit eius dolor ut ducimus deserunt. Ut eveniet "
        "rerum ut beatae blanditiis et atque quidem a perferendis quasi qui "
        "magni optio. </p><p>Sit odit maxime cum aliquid omnis et consequatur "
        "amet in corrupti quia. Id unde possimus eum modi earum sed eius vero "
        "rem corporis voluptatem a obcaecati impedit est expedita incidunt ut "
        "labore dolor. Est deserunt similique aut facilis ducimus ut totam "
        "illo sed odit nihil eos facere voluptates qui asperiores optio. "
        "</p><p>Quo labore doloribus in dolorem libero qui nihil amet quo "
        "ipsum optio qui aspernatur voluptas et ducimus ducimus est atque "
        "asperiores. Aut voluptatem sunt est internos quis in voluptatem "
        "doloremque qui accusantium natus ut dolor culpa est laborum sunt. Aut "
        "quia quisquam qui libero provident cum consequatur minima et earum "
        "molestias. </p><p>Aut perspiciatis adipisci ex omnis aliquid vel "
        "omnis eius vel nulla placeat ea perferendis quia et fugiat odio id "
        "provident quas. Eum voluptas veritatis ad dolorum aspernatur qui "
        "obcaecati quia. </p><p>Qui facilis culpa ea harum possimus aut sunt "
        "temporibus ab porro vitae et molestiae tenetur aut quas optio ea "
        "fugit internos. Aut omnis omnis quo repellat quae qui laborum "
        "adipisci quo excepturi nostrum ut labore nobis. </p>";
  }

  void TearDown() override {
    std::filesystem::remove_all(pe_files_tmp_dir_path);
    std::filesystem::remove_all(not_pe_file_tmp_dir_path);
    std::filesystem::remove_all(unsigned_file_tmp_dir_path);
  }

  std::vector<std::string> test_data_;
  std::string test_text_;
  std::string not_pe_file_path_;
  std::string unsigned_file_path_;
  std::filesystem::directory_iterator dir_iterator_;
};

}  // namespace

TestEnvironment::TestEnvironment(const std::string& pe_files,
                                 const std::string& not_pe_file,
                                 const std::string& unsigned_file) {
  pe_files_for_tests_path = pe_files;
  not_pe_file_path = not_pe_file;
  unsigned_file_path = unsigned_file;
}

TEST_F(WdpeTest, write) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    for (const auto& test_str : test_data_) {
      wdpe::write(file_path, test_str.c_str(), test_str.size());
      ASSERT_TRUE(verify_signature(file_path));
      ASSERT_EQ(0, std::filesystem::file_size(file_path) % 8);

      const auto written_data = wdpe::read(file_path);

      ASSERT_EQ(test_str.size(), written_data.size());
      for (int i = 0; i < test_str.size(); ++i) {
        ASSERT_EQ(test_str[i], written_data[i]);
      }

      wdpe::write(file_path, test_text_.c_str(), test_text_.size());
      ASSERT_TRUE(verify_signature(file_path));
      ASSERT_EQ(0, std::filesystem::file_size(file_path) % 8);

      const auto written_data1 = wdpe::read(file_path);

      ASSERT_EQ(test_text_.size(), written_data1.size());
      for (int i = 0; i < test_text_.size(); ++i) {
        ASSERT_EQ(test_text_[i], written_data1[i]);
      }
    }
  }

  ASSERT_THROW(
      {
        wdpe::write(not_pe_file_path_, test_text_.c_str(), test_text_.size());
      },
      wdpe::unknown_file_format);

  ASSERT_THROW(
      {
        wdpe::write(unsigned_file_path_, test_text_.c_str(), test_text_.size());
      },
      wdpe::auth_signature_not_found);

  const auto file_path = dir_iterator_->path().string();
  ASSERT_TRUE(update_wdpe_addr(file_path, 123));
  ASSERT_THROW(
      { wdpe::write(file_path, test_text_.c_str(), test_text_.size()); },
      wdpe::payload_corrupted);

  ASSERT_TRUE(
      update_wdpe_addr(file_path, std::filesystem::file_size(file_path) + 999));
  ASSERT_THROW(
      { wdpe::write(file_path, test_text_.c_str(), test_text_.size()); },
      wdpe::payload_corrupted);
}

TEST_F(WdpeTest, delete_payload) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    const auto file_size = std::filesystem::file_size(file_path);

    for (const auto& test_str : test_data_) {
      wdpe::write(file_path, test_str.c_str(), test_str.size());

      wdpe::delete_payload(file_path);
      ASSERT_TRUE(verify_signature(file_path));
      ASSERT_FALSE(wdpe::is_payload_present(file_path));
      ASSERT_TRUE(std::filesystem::file_size(file_path) == file_size);
    }

    wdpe::write(file_path, test_text_.c_str(), test_text_.size());

    wdpe::delete_payload(file_path);
    ASSERT_TRUE(verify_signature(file_path));
    ASSERT_FALSE(wdpe::is_payload_present(file_path));
    ASSERT_TRUE(std::filesystem::file_size(file_path) == file_size);
  }

  EXPECT_THROW({ wdpe::delete_payload(not_pe_file_path_); },
               wdpe::unknown_file_format);

  const auto file_path = dir_iterator_->path().string();
  wdpe::write(file_path, test_text_.c_str(), test_text_.size());

  ASSERT_TRUE(update_wdpe_addr(file_path, 123));
  ASSERT_THROW({ wdpe::delete_payload(file_path); }, wdpe::payload_corrupted);

  ASSERT_TRUE(
      update_wdpe_addr(file_path, std::filesystem::file_size(file_path) + 999));
  ASSERT_THROW({ wdpe::delete_payload(file_path); }, wdpe::payload_corrupted);
}

TEST_F(WdpeTest, read) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    const auto written_data = wdpe::read(file_path);
    ASSERT_TRUE(written_data.empty());

    for (const auto& test_str : test_data_) {
      wdpe::write(file_path, test_str.c_str(), test_str.size());

      const auto written_data = wdpe::read(file_path);
      ASSERT_EQ(test_str.size(), written_data.size());
      for (int i = 0; i < test_str.size(); ++i) {
        ASSERT_EQ(test_str[i], written_data[i]);
      }

      wdpe::write(file_path, test_text_.c_str(), test_text_.size());

      const auto written_data1 = wdpe::read(file_path);
      ASSERT_EQ(test_text_.size(), written_data1.size());
      for (int i = 0; i < test_text_.size(); ++i) {
        ASSERT_EQ(test_text_[i], written_data1[i]);
      }
    }
  }

  ASSERT_THROW({ wdpe::read(not_pe_file_path_); }, wdpe::unknown_file_format);

  const auto file_path = dir_iterator_->path().string();

  ASSERT_TRUE(update_wdpe_data(file_path, 666));
  ASSERT_THROW({ wdpe::read(file_path); }, wdpe::payload_corrupted);

  wdpe::delete_payload(file_path);
  wdpe::write(file_path, test_text_.c_str(), test_text_.size());

  ASSERT_TRUE(update_wdpe_addr(file_path, 123));
  ASSERT_THROW({ wdpe::read(file_path); }, wdpe::payload_corrupted);

  ASSERT_TRUE(
      update_wdpe_addr(file_path, std::filesystem::file_size(file_path) + 999));
  ASSERT_THROW({ wdpe::read(file_path); }, wdpe::payload_corrupted);
}

TEST_F(WdpeTest, write_raw_data) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    for (const auto& test_str : test_data_) {
      const auto test_str_size = test_str.size();

      const auto addr =
          wdpe::write_raw_data(file_path, test_str.c_str(), test_str_size);
      ASSERT_TRUE(verify_signature(file_path));
      ASSERT_EQ(0, std::filesystem::file_size(file_path) % 8);

      const auto written_data =
          wdpe::read_raw_data(file_path, addr, test_str_size);

      ASSERT_EQ(test_str_size, written_data.size());
      for (int i = 0; i < test_str_size; ++i) {
        ASSERT_EQ(test_str[i], written_data[i]);
      }

      const auto addr1 = wdpe::write_raw_data(file_path, test_text_.c_str(),
                                              test_text_.size());
      ASSERT_TRUE(verify_signature(file_path));

      const auto written_data1 =
          wdpe::read_raw_data(file_path, addr1, test_text_.size());

      ASSERT_EQ(test_text_.size(), written_data1.size());
      for (int i = 0; i < test_text_.size(); ++i) {
        ASSERT_EQ(test_text_[i], written_data1[i]);
      }
    }
  }

  ASSERT_THROW(
      {
        wdpe::write_raw_data(not_pe_file_path_, test_text_.c_str(),
                             test_text_.size());
      },
      wdpe::unknown_file_format);

  ASSERT_THROW(
      {
        wdpe::write_raw_data(unsigned_file_path_, test_text_.c_str(),
                             test_text_.size());
      },
      wdpe::auth_signature_not_found);
}

TEST_F(WdpeTest, read_raw_data) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    for (const auto& test_str : test_data_) {
      const auto test_str_size = test_str.size();

      const auto addr =
          wdpe::write_raw_data(file_path, test_str.c_str(), test_str_size);

      ASSERT_THROW({ wdpe::read_raw_data(file_path, 1, test_text_.size()); },
                   wdpe::invalid_data_addr);

      ASSERT_THROW(
          {
            wdpe::read_raw_data(file_path,
                                std::filesystem::file_size(file_path) + 99);
          },
          wdpe::invalid_data_addr);

      ASSERT_THROW(
          { wdpe::read_raw_data(file_path, addr, test_str_size + 10); },
          wdpe::invalid_data_addr);

      const auto written_data =
          wdpe::read_raw_data(file_path, addr, test_str_size);

      ASSERT_EQ(test_str_size, written_data.size());
      for (int i = 0; i < test_str_size; ++i) {
        ASSERT_EQ(test_str[i], written_data[i]);
      }

      const auto written_data1 = wdpe::read_raw_data(file_path, addr);

      const auto expected_size = test_str_size +
                                 std::filesystem::file_size(file_path) -
                                 (addr + test_str_size);
      ASSERT_EQ(expected_size, written_data1.size());

      for (int i = 0; i < expected_size; ++i) {
        if (i < test_str_size) {
          ASSERT_EQ(test_str[i], written_data1[i]);
        } else {
          ASSERT_EQ('\0', written_data1[i]);
        }
      }

      const auto addr1 = wdpe::write_raw_data(file_path, test_text_.c_str(),
                                              test_text_.size());

      const auto written_data2 =
          wdpe::read_raw_data(file_path, addr1, test_text_.size());

      ASSERT_EQ(test_text_.size(), written_data2.size());
      for (int i = 0; i < test_text_.size(); ++i) {
        ASSERT_EQ(test_text_[i], written_data2[i]);
      }
    }
  }

  ASSERT_THROW({ wdpe::read_raw_data(not_pe_file_path_, 1); },
               wdpe::unknown_file_format);

  const auto res = wdpe::read_raw_data(unsigned_file_path_, 1);
  ASSERT_TRUE(res.empty());
}

TEST_F(WdpeTest, delete_raw_data) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    const auto file_size = std::filesystem::file_size(file_path);

    for (const auto& test_str : test_data_) {
      const auto addr =
          wdpe::write_raw_data(file_path, test_str.c_str(), test_str.size());

      ASSERT_THROW({ wdpe::delete_raw_data(file_path, 5); },
                   wdpe::invalid_data_addr);

      ASSERT_THROW(
          {
            wdpe::delete_raw_data(file_path,
                                  std::filesystem::file_size(file_path) + 10);
          },
          wdpe::invalid_data_addr);

      wdpe::delete_raw_data(file_path, addr);
      ASSERT_TRUE(verify_signature(file_path));
      ASSERT_TRUE(std::filesystem::file_size(file_path) == file_size);
    }

    const auto addr1 =
        wdpe::write_raw_data(file_path, test_text_.c_str(), test_text_.size());

    wdpe::delete_raw_data(file_path, addr1);
    ASSERT_TRUE(verify_signature(file_path));
    ASSERT_TRUE(std::filesystem::file_size(file_path) == file_size);
  }

  ASSERT_THROW({ wdpe::delete_raw_data(not_pe_file_path_, 1); },
               wdpe::unknown_file_format);
}

TEST_F(WdpeTest, read_image_dir_entry_security) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    const auto data_dir = wdpe::read_image_dir_entry_security(file_path);
    const auto expected_data_dir = get_image_dir_entry_security(file_path);

    ASSERT_EQ(expected_data_dir.virtual_address, data_dir.virtual_address);
    ASSERT_EQ(expected_data_dir.size, data_dir.size);
  }

  ASSERT_THROW({ wdpe::read_image_dir_entry_security(not_pe_file_path_); },
               wdpe::unknown_file_format);
}

TEST_F(WdpeTest, delete_auth_signature) {
  for (auto const& dir_entry : dir_iterator_) {
    const auto file_path = dir_entry.path().string();

    for (const auto& test_str : test_data_) {
      wdpe::delete_auth_signature(file_path);
      ASSERT_FALSE(verify_signature(file_path));
    }
  }
}

}  // namespace wdpe