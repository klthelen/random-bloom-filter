// ---------------------------------------------
// NAME: Kirk Thelen           User ID: klthelen
// DUE DATE: 10/7/2022
// PROJ1
// FILE NAME: RBFGen.cpp
// PROGRAM PURPOSE:
//     This file contains the main function to
//     generate a RBF, fill it with the 10,000
//     malicious IP addresses indicated in the
//     specification, and output the bloom
//     filter to a text file called RBFRow1.txt.
// ---------------------------------------------

#include <iostream>  // std::cout
#include <stdlib.h>  // atoi
#include <string>    // std::string
#include <fstream>   // ofstream
#include "RBF.h"     // RBF class implementation

int main(int argc, char *argv[]) {
  // ********** PARAMETER CHECKING ********** //
  if (argc != 2) {
    std::cout << "usage: ./RBFGen <m>" << std::endl;
    std::cout.flush();
    exit(1);
  }
  int m = atoi(argv[1]);
  RBF *rbf = new RBF(m);
  std::fstream file;
  
  file.open("RBFRow1.txt", std::fstream::out);
  rbf->fillFilter();
  rbf->printFilter(file);
  file.close();
  
  delete rbf;
}
