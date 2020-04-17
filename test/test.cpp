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
