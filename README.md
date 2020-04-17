# hinspector

C++ one-header library to inspect cpu and memory usage (Windows only)


## Snippet

```cpp
#include <iostream>

#include <hinspector/hinspector.hpp>



int main() {

  using namespace  std;

  auto const machine = hinspector::machine::identify();

  cout << machine << endl;

  if(machine.processor.is_intel())
    cout << "Intel" << endl;
  else if(machine.processor.is_amd())
    cout << "AMD" << endl;
  else
    cout << machine.processor.vendor << endl;

  hinspector::usage::machine usage;
  cout << "Usage: " << usage.slice() << endl;

  return 0;
}
```

Possible output:
```
processor: Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz (8 cores), memory: 16 Gb, system: Windows 10
Intel
Usage: processor: 51%, memory: 2 Mb (total 59%)
```

## Synopsis

```cpp
namespace hinspector {

struct processor {

  using size_type = size_t;

  std::string title;
  size_type cores_count{0};
  std::string vendor;

  explicit operator bool () const noexcept;
  bool is_intel() const noexcept; // only for x86
  bool is_amd() const noexcept;   // only for x86

  static processor build(std::string brand,
                         size_type cores_count,
                         std::string vendor = "") noexcept;
  
  static processor identify();

}; // processor



struct memory {

  using size_type = size_t;

  size_type physical{0};  // in Mb

  explicit operator bool () const noexcept;
  
  static memory identify();

}; // memory



struct operating_system {

  std::string title;
  unsigned major_version{0};
  unsigned minor_version{0};

  explicit operator bool () const noexcept;
  
  static operating_system identify();
  
}; // operating_system



struct machine {

  processor processor;
  memory memory;
  operating_system operating_system;

  static machine identify();

}; // machine



namespace usage {


struct processor {

  unsigned total_usage{0};  // in percents

  processor& slice() noexcept {

}; // processor



struct memory {

  using size_type = size_t;

  size_type resident_set_size{0};
  unsigned total_usage{0};

  memory& slice() noexcept;
  
}; // memory



struct machine {

  processor processor;
  memory memory;

  machine& slice() noexcept;
  
}; // machine


} // usage


} // hinspector

```