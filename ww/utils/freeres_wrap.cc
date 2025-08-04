
extern "C" void call_freeres(); 

namespace __gnu_cxx {
  // match the real signature exactly:
  void __freeres() noexcept;
}

extern "C" void call_freeres() {
    __gnu_cxx::__freeres();   
}