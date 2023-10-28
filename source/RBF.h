// ---------------------------------------------
// NAME: Kirk Thelen           User ID: klthelen
// DUE DATE: 10/7/2022
// PROJ1
// FILE NAME: RBF.h
// PROGRAM PURPOSE:
//     This file contains the definitions for
//     the RBF class.
// ---------------------------------------------
#include <iostream>
#include <string>
#include <fstream>

class RBF {
private:
  int m;                              // The size, m, of the filter
  bool *filter;                       // Bool pointer to the filter array
  int hashMod(std::string, int);      // Helper function

public:
  RBF(int);                           // Parameterized Constructor for RBFGen
  RBF(std::fstream&);                 // Parameterized Constructor for IPCheck
  ~RBF();                             // Destructor to clean up *filter
  void fillFilter();                  // Fills filter with 10,000 malicious IP addresses
  bool checkFilter(std::string);      // Checks the filter for a given IP
  void printFilter(std::fstream&);    // Prints the filter to the given file stream
  void loadFilter(std::fstream&);     // Loads the filter from the given file stream
};
