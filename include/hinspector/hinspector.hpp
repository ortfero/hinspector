#pragma once



#include <cstdint>
#include <string>
#include <iosfwd>

#if _WIN32


namespace hinspector { namespace detail {

struct os_version_info {
  uint32_t dwOSVersionInfoSize;
  uint32_t dwMajorVersion;
  uint32_t dwMinorVersion;
  uint32_t dwBuildNumber;
  uint32_t dwPlatformId;
  wchar_t  szCSDVersion[ 128 ];     // Maintenance string for PSS usage
  uint16_t   wServicePackMajor;
  uint16_t   wServicePackMinor;
  uint16_t   wSuiteMask;
  char  wProductType;
  char  wReserved;
}; // os_version_info

constexpr char ver_nt_workstation = 0x0000001;

extern "C" long __stdcall RtlGetVersion(os_version_info*);

struct system_info {
    union {
        uint32_t dwOemId;          // Obsolete field...do not use
        struct {
            uint16_t wProcessorArchitecture;
            uint16_t wReserved;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    uint32_t dwPageSize;
    void* lpMinimumApplicationAddress;
    void* lpMaximumApplicationAddress;
    uint32_t* dwActiveProcessorMask;
    uint32_t dwNumberOfProcessors;
    uint32_t dwProcessorType;
    uint32_t dwAllocationGranularity;
    uint16_t wProcessorLevel;
    uint16_t wProcessorRevision;
}; // system_info


extern "C" void __stdcall GetSystemInfo(system_info*);
extern "C" int __stdcall GetPhysicallyInstalledSystemMemory(uint64_t*);


struct memory_status_ex {
  uint32_t dwLength;
  uint32_t dwMemoryLoad;
  uint64_t ullTotalPhys;
  uint64_t ullAvailPhys;
  uint64_t ullTotalPageFile;
  uint64_t ullAvailPageFile;
  uint64_t ullTotalVirtual;
  uint64_t ullAvailVirtual;
  uint64_t ullAvailExtendedVirtual;
}; // memory_status_ex


extern "C" int __stdcall GlobalMemoryStatusEx(memory_status_ex* ms);

union filetime {
  struct {
    uint32_t dwLowDateTime;
    uint32_t dwHighDateTime;
  };
  uint64_t ullDateTime;
}; // filetime


extern "C" int __stdcall GetSystemTimes(filetime* lpIdleTime,
                                        filetime* lpKernelTime,
                                        filetime* lpUserTime);

extern "C" void* __stdcall GetCurrentProcess();


struct process_memory_counters {
  uint32_t cb;
  uint32_t PageFaultCount;
  size_t PeakWorkingSetSize;
  size_t WorkingSetSize;
  size_t QuotaPeakPagedPoolUsage;
  size_t QuotaPagedPoolUsage;
  size_t QuotaPeakNonPagedPoolUsage;
  size_t QuotaNonPagedPoolUsage;
  size_t PagefileUsage;
  size_t PeakPagefileUsage;
}; // process_memory_counters


extern "C" int __stdcall
K32GetProcessMemoryInfo(void* process,
                        process_memory_counters* ppsmemCounters,
                        uint32_t cb);


} } // detail // hinspector


#if _MSC_VER


#pragma comment(lib, "ntdll.lib")

#include <intrin.h>

#else

#error Unsupported compiler

#endif

#else

#error Unsupported system

#endif



namespace hinspector {



namespace detail {

#if defined (_MSC_VER)

#if defined (_M_X86) || defined (_M_X64)

  struct cpuid {

    void identify(std::string& vendor, std::string& brand) noexcept {

      char vendor_data[16];
      __cpuidex((int*)regs_, 0, 0);

      memcpy(vendor_data, ebx<char>(), 4);
      memcpy(vendor_data + 4, edx<char>(), 4);
      memcpy(vendor_data + 8, ecx<char>(), 4);
      vendor_data[12] = '\0';
      vendor = vendor_data;

      char brand_data[64]; char* brand_ptr = brand_data;
      for(uint32_t i = 0x80000002; i != 0x80000005; ++i) {
        __cpuidex((int*)regs_, i, 0);
        memcpy(brand_ptr, eax<char>(), 4); brand_ptr += 4;
        memcpy(brand_ptr, ebx<char>(), 4); brand_ptr += 4;
        memcpy(brand_ptr, ecx<char>(), 4); brand_ptr += 4;
        memcpy(brand_ptr, edx<char>(), 4); brand_ptr += 4;
      }
      brand_data[48] = '\0';
      brand = brand_data;
    }

    template<typename T> T const* eax() const noexcept { return (T*)&regs_[0]; }
    template<typename T> T const* ebx() const noexcept { return (T*)&regs_[1]; }
    template<typename T> T const* ecx() const noexcept { return (T*)&regs_[2]; }
    template<typename T> T const* edx() const noexcept { return (T*)&regs_[3]; }

  private:

    uint32_t regs_[4];

  };

#endif // _M_X86 || _M_X64

#endif // _MSC_VER

} // detail



struct processor {

  using size_type = size_t;

  std::string title;
  size_type cores_count{0};  
  std::string vendor;

  processor() noexcept = default;
  processor(processor const&) = default;
  processor& operator = (processor const&) = default;
  processor(processor&&) noexcept = default;
  processor& operator = (processor&&) noexcept = default;
  explicit operator bool () const noexcept { return cores_count != 0; }

#if defined (_M_AMD64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)

  bool is_intel() const noexcept { return vendor == "GenuineIntel"; }
  bool is_amd() const noexcept { return vendor == "AuthenticAMD"; }

#else

#error Unsupported processor

#endif


  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, processor const& p) noexcept {
      if(!p)
        return os << "Undefined";
      os << p.title << " (" << p.cores_count << " cores)";
      return os;
    }



  static processor build(std::string brand, size_type cores_count, std::string vendor = "") noexcept {
    return processor{std::move(brand), cores_count, std::move(vendor)};
  }



#if _WIN32

  static processor identify() {
    detail::system_info si;
    detail::GetSystemInfo(&si);
    std::string vendor, title;
    detail::cpuid cpuid;
    cpuid.identify(vendor, title);
    return processor{std::move(title), si.dwNumberOfProcessors, std::move(vendor)};
  }

#endif

private:


  processor(std::string title, size_type cores_count, std::string vendor) noexcept:
    title{std::move(title)}, cores_count{cores_count}, vendor{std::move(vendor)}
  { }

}; // processor



struct memory {

  using size_type = size_t;

  size_type physical{0};

  memory() noexcept = default;
  memory(memory const&) noexcept = default;
  memory& operator = (memory const&) noexcept = default;
  explicit operator bool () const noexcept { return physical != 0; }

  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, memory const& m) noexcept {
      if(!m)
        return os << "Undefined";
      if(m.physical < 1024)
        os << m.physical << " Mb";
      else
        os << (double(m.physical) / 1024) << " Gb";
      return os;
    }

#if _WIN32

  static memory identify() {
    uint64_t physical;
    detail::GetPhysicallyInstalledSystemMemory(&physical);
    physical /= 1024;
    return memory{physical};
  }

#endif

private:

  memory(size_type physical) noexcept:
    physical{physical}
  { }

}; // memory



struct operating_system {

  std::string title;
  unsigned major_version{0};
  unsigned minor_version{0};

  operating_system() noexcept = default;
  operating_system(operating_system const&) = default;
  operating_system& operator = (operating_system const&) = default;
  operating_system(operating_system&&) noexcept = default;
  operating_system& operator = (operating_system&&) noexcept = default;
  explicit operator bool () const noexcept { return !title.empty(); }

  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, operating_system const& system) noexcept {
      if(!system)
        return os << "Undefined";
      os << system.title << ' ' << system.major_version;
      if(system.minor_version != 0)
        os << '.' << system.minor_version;
      return os;
    }

#if _WIN32

  static operating_system identify() {

    std::string title{"Windows"};

    detail::os_version_info vi;
    vi.dwOSVersionInfoSize = sizeof(vi);
    detail::RtlGetVersion(&vi);

    if(vi.wProductType != detail::ver_nt_workstation)
      title += " Server";

    return operating_system{"Windows", vi.dwMajorVersion, vi.dwMinorVersion};
  }

#endif

private:

  operating_system(std::string title, unsigned major_version, unsigned minor_version) noexcept:
    title{std::move(title)},
    major_version{major_version},
    minor_version{minor_version}
  { }


}; // operating_system



struct machine {

  processor processor;
  memory memory;
  operating_system operating_system;

  machine() noexcept = default;
  machine(machine const&) = default;
  machine& operator = (machine const&) = default;
  machine(machine&&) noexcept = default;
  machine& operator = (machine&&) noexcept = default;



  static machine identify() {
    return machine{
      hinspector::processor::identify(),
      hinspector::memory::identify(),
      hinspector::operating_system::identify()
    };
  }



  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, machine const& m) noexcept {
      os << "processor: " << m.processor
         << ", memory: " << m.memory
         << ", system: " << m.operating_system;
      return os;
    }



private:

  machine(struct processor const& processor,
          struct memory const& memory,
          struct operating_system const& operating_system):
    processor(processor),
    memory(memory),
    operating_system(operating_system)
  { }

}; // machine



namespace usage {



#if _WIN32

struct processor {

  processor() noexcept = default;
  processor(processor const&) noexcept = default;
  processor& operator = (processor const&) noexcept = default;
  explicit operator bool () const noexcept { return total_usage != 0; }



  unsigned total_usage{0};



  processor& slice() noexcept {

    detail::filetime idle_time, kernel_time, user_time;
    if(!detail::GetSystemTimes(&idle_time, &kernel_time, &user_time))
      return *this;


    int64_t const used = kernel_time.ullDateTime + user_time.ullDateTime;
    int64_t const idle = idle_time.ullDateTime;



    int64_t const used_delta = used - used_time_;
    int64_t const idle_delta = idle - idle_time_;

    used_time_ = used;
    idle_time_ = idle;

    total_usage = unsigned(used_delta * 100 / (used_delta + idle_delta));

    return *this;
  }



  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, processor const& p) noexcept {
      os << p.total_usage << '%';
      return os;
    }


private:

  int64_t used_time_{0};
  int64_t idle_time_{0};
}; // processor



struct memory {

  using size_type = size_t;

  memory() noexcept = default;
  memory(memory const&) noexcept = default;
  memory& operator = (memory const&) noexcept = default;

  size_type resident_set_size{0};
  unsigned total_usage{0};



  memory& slice() noexcept {

    resident_set_size = 0;
    total_usage = 0;

    detail::process_memory_counters pmc;
    pmc.cb = sizeof(pmc);
    if(!detail::K32GetProcessMemoryInfo(detail::GetCurrentProcess(), &pmc, sizeof (pmc)))
      return *this;
    resident_set_size = pmc.WorkingSetSize / (1024 * 1024);

    detail::memory_status_ex msx;
    msx.dwLength = sizeof (msx);
    if(!detail::GlobalMemoryStatusEx(&msx))
      return *this;

    total_usage = unsigned(msx.ullAvailPhys * 100 / msx.ullTotalPhys);
    return *this;
  }



  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, memory const& m) noexcept {
      os << m.resident_set_size << " Mb (total " << m.total_usage << "%)";
      return os;
    }


}; // memory

#endif



struct machine {

  processor processor;
  memory memory;

  machine& slice() noexcept {
    processor.slice();
    memory.slice();
    return *this;
  }


  template<typename charT, typename traits> friend
  std::basic_ostream<charT, traits>&
    operator << (std::basic_ostream<charT, traits>& os, machine const& m) noexcept {
      os << "processor: " << m.processor << ", memory: " << m.memory;
      return os;
    }


}; // machine



} // usage



} // hinspector
