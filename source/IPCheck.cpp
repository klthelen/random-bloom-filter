// ---------------------------------------------
// NAME: Kirk Thelen           User ID: klthelen
// DUE DATE: 10/7/2022
// PROJ1
// FILE NAME: IPCheck.cpp
// ---------------------------------------------
#include <iostream>
#include <stdlib.h>
#include <string>
#include <fstream>

#include "RBF.h"

int main(int argc, char *argv[]) {
  // ********** PARAMETER CHECKING ********** //
  if (argc != 3) {
    std::cout << "usage: ./IPCheck <file.txt> <ip address xxx.xxx.x.xxx>" << std::endl;
    std::cout.flush();
    exit(1);
  }
  std::string filename = argv[1];
  std::string ip = argv[2];
  std::fstream file;

  // Open file and read it into the bloom filter
  file.open(filename, std::fstream::in);  
  RBF *rbf = new RBF(file);

  // Check the bloom filter for the IP
  // If the IP is in the RBF, output "block"
  // Otherwise, output "true"
  if (rbf->checkFilter(ip) == true) {
    std::cout << "block" << std::endl;
  }
  else {
    std::cout << "pass" << std::endl;
  }

  file.close();
  delete rbf;
}
