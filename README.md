# wdpe
[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Windows/Linux/macOS header-only/compile C++11 library without dependencies for writing data to signed PE files (exe/dll/etc...) without invalidating or damaging the authenticode digital signature of a file. Allows you to write data to a signed file, read, delete previously written data, delete authenticode digital signature of a file, read OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY], update file checksum.


## Usage samples

Write, overwrite, read and delete data from a signed file without invalidating or damaging the authenticode digital signature.

```cpp
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

    // Overwrite data.
    const std::string new_data{"New data."};
    wdpe::write(file_path, new_data.c_str(), new_data.size());
    const auto overwritten_data = wdpe::read(file_path);

    // Delete data written by the wdpe library.
    wdpe::delete_payload(file_path);

    // Check if the file contains data written by the wdpe library.
    if (!wdpe::is_payload_present(file_path)) {
      std::cout << "No data" << std::endl;
    }

  } catch (const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }
}
```

wdpe::write writes data in the wdpe library format. In addition to the data itself, additional information is written - a special signature, to determine that the message was written in the wpde library format, the address and size of the written user data, as well as their checksum to check if the data has been corrupted. The checksum is checked in wdpe::read. Functions wdpe::write, wdpe::read, wdpe::delete_payload, wdpe::is_payload_present work with data in the wdpe library format.

But a number of lower-level functions are also provided: wdpe::write_raw_data, wdpe::read_raw_data, wdpe::delete_raw_data, who write the data as is, without adding additional information. Therefore wdpe::read_raw_data and wdpe::delete_raw_data require the address to which the data was written, and wdpe::write_raw_data returns the address to which the data was written.

```cpp
#include <wdpe/wdpe.hpp>
#include <string>
#include <vector>
#include <iostream>

int main() {
  const std::string file_path{"path/to/signed/pe/file.exe"};
  const std::string data{"Lorem ipsum dolor sit amet."};

  // Write data to the file.
  const auto data_address =
      wdpe::write_raw_data(file_path, data.c_str(), data.size());

  // Read data from the file.
  const auto written_data =
      wdpe::read_raw_data(file_path, data_address, data.size());

  // Delete data written by the wdpe library.
  wdpe::delete_raw_data(file_path, data_address);
}
```

Read OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].

```cpp
#include <iostream>
#include <string>
#include <vector>
#include <wdpe/wdpe.hpp>

int main() {
  const std::string file_path{"D:/projects/test10/info.exe"};
  const std::string data{"Lorem ipsum dolor sit amet."};

  // Write data to the file.
  wdpe::write_raw_data(file_path, data.c_str(), data.size());

  // Read OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]
  // and use this structure for read written data from the end of the section
  // at address OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress.
  const auto data_dir = wdpe::read_image_dir_entry_security(file_path);

  std::ifstream fs;
  fs.exceptions(std::fstream::badbit | std::fstream::failbit);
  fs.open(file_path, std::fstream::binary | std::fstream::in);

  // The data written by the wdpe library is located at the end of the section
  // at OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
  const auto section_end_addr = data_dir.virtual_address + data_dir.size;

  // After the written data, up to 7 zero alignment bytes are added.
  // Getting the number of these bytes. In this case, the written data does not
  // contain zero bytes, so just count the available zero bytes at the end of
  // the section.
  int i = 0;
  for (; i < 8; ++i) {
    fs.seekg(section_end_addr - i - 1);
    char buf;
    fs.read(&buf, sizeof(buf));
    if (buf != '\0') {
      break;
    }
  }

  // Obtaining the address of the recorded data in the file. We subtract from
  // the address of the end of the section the number of zero bytes torn out and
  // the size of the recorded data.
  const auto data_address = section_end_addr - i - data.size();

  // Reading the written data.
  fs.seekg(data_address);
  std::vector<char> written_data(data.size());
  fs.read(written_data.data(), written_data.size());

  // Delete data written by the wdpe library.
  wdpe::delete_raw_data(file_path, data_address);
}
```

Deleting the digital signature of a file.

```cpp
#include <iostream>
#include <string>
#include <vector>
#include <wdpe/wdpe.hpp>

int main() {
  const std::string file_path{"path/to/signed/pe/file.exe"};

  // Deleting the digital signature of a file.
  wdpe::delete_auth_signature(file_path);

  // Reading the address and size of a section with digital signature data.
  // After deleting the signature, it should be empty.
  const auto data_dir = wdpe::read_image_dir_entry_security(file_path);
  if (data_dir.virtual_address == 0) {
    std::cout
        << "PE file section with authenticode digital signature data is empty."
        << std::endl;
  }
}
```
## Integration
### CMake
Add the library subdirectory to your project's CMakeLists.txt. Then link the interface target wdpe_header_only in case you want to use the header-only library. Link the wdpe target if including as a static library. To include wdpe as a dynamic library, set the option WDPE_BUILD_SHARED=ON and link the wdpe target.

Header-only:
```cmake
add_subdirectory(third_party/wdpe) # path to directory with wdpe lib
target_link_libraries(your_project_target_name PRIVATE wdpe_header_only)
```

Static:
```cmake
add_subdirectory(third_party/wdpe) # path to directory with wdpe lib
target_link_libraries(your_project_target_name PRIVATE wdpe)
```

Shared:
```cmake
set(WDPE_BUILD_SHARED ON CACHE BOOL "Build wdpe shared library")
add_subdirectory(third_party/wdpe) # path to directory with wdpe lib
target_link_libraries(your_project_target_name PRIVATE wdpe)
```
If you include wdpe as a header-only library, include the header file in your project files:
```cpp
#include <wdpe/wdpe_inl.hpp>
```

When including a library as static or dynamic, include the header file in your project files:
```cpp
#include <wdpe/wdpe.hpp>
```

### Visual Studio
#### Including the header-only library:
1. Go to Properties -> C/C++ -> Additional Include Directories and add the path to the library directory "wdpe/include".
2. Properties -> Advanced -> Character Set must be set to Multi-Byte.
3. Include header file: ```#include <wdpe/wdpe_inl.hpp> ```

#### Including the static library:
```
git clone https://github.com/dmtai/wdpe.git
cd wdpe
mkdir build
cd build
cmake ..
cmake --build . --config Release --target wdpe
```
- Go to Properties -> C/C++ -> Additional Include Directories and add the library directory "wdpe/include".
- Properties -> Advanced -> Character Set must be set to Multi-Byte.
- Properties -> Linker-> General-> Additional Library Directories specify the path to the .lib file (build/Release directory)
- Properties -> Linker -> Input -> Additional Dependencies add the library file name "wdpe.lib"
- Include header file: ```#include <wdpe/wdpe.hpp> ```

#### Including the dynamic library:
Build the dll using cmake and the WDPE_BUILD_SHARED option and include it to the project. Include the ```#include <wdpe/wdpe.hpp>``` header.

## Documentation
Documentation is located in the [wiki](https://github.com/dmtai/wdpe/wiki/Documentation) pages.
