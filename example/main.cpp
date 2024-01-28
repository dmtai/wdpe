#include <wdpe/wdpe.hpp>
#include <string>
#include <vector>
#include <iostream>

int main() {
  const std::string file_path{"path/to/signed/pe/file.exe"};
  const std::string data{"Lorem ipsum dolor sit amet."};

  try {
    // Write data to the file.
    wdpe::write(file_path, data.c_str(), data.size());

    // Read data from the file.
    const auto written_data = wdpe::read(file_path);

    std::cout << "Written data: ";
    for(const auto& s : written_data) {
      std::cout << s;
    }
  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
    return 1;
  }

  return 0;
}