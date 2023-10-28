// ---------------------------------------------
// NAME: Kirk Thelen           User ID: klthelen
// DUE DATE: 10/7/2022
// PROJ 1
// FILE NAME: RBF.cpp
// PROGRAM PURPOSE:
//     This file contains the implementations
//     for the RBF class. 
// ---------------------------------------------
#include <iostream>  // std::cout
#include <stdlib.h>
#include <string>    // std::string
#include <fstream>
#include "RBF.h"
#include "sha256.h"

// ---------------------------------------------
// CONSTRUCTOR RBF::RBF(int)
//     Constructs and initializes an RBF with
//     length m.
// POSTCONDITION:
//     The RBF SHOULD be filled with malicious
//     ip addresses by calling loadFilter().
// PARAMETER USAGE:
//     length :  The value, m, to be the length
//               of the bloom filter.
// FUNCTION CALLED:
//     sha256(), hashMod()
// ---------------------------------------------
RBF::RBF(int length) {
  m = length;
  filter = new bool[m];

  // Initialize RBF using key of 0
  for (int i = 0; i < m; i++) {
    std::string row = sha256("0" + std::to_string(i));
    int H = hashMod(row, 2);
    if (H == 0) {
      filter[i] = false;
    }
    else {
      filter[i] = true;
    }
  }
}

// ---------------------------------------------
// CONSTRUCTOR RBF::RBF()
//     Constructs an RBF by reading the data
//     from an fstream.
// POSTCONDITION:
//     The RBF will now be full of the malicious
//     IP addresses and MAY be used to check
//     those IP addresses. With the checkFilter
//     function.
// PARAMETERS:
//     ostr : The fstream to load the bloom
//            filter from.
// FUNCTIONS CALLED:
//     loadFilter()
// ---------------------------------------------
RBF::RBF(std::fstream &ostr) {
  filter = nullptr;
  loadFilter(ostr);
}

// ---------------------------------------------
// DESTRUCTOR RBF::~RBF()
//     Destructs an RBF, freeing the memory of
//     the filter.
// ---------------------------------------------
RBF::~RBF() {
  delete [] filter;
  filter = nullptr;
}

// ---------------------------------------------
// FUNCTION int RBF::hashMod(std::string, int)
//     Takes the last 5 characters of a
//     hexstring (which correspond to the last
//     20 digits of their binary value) and
//     modulos them.
// PRECONDITION:
//     The provided hexstring SHOULD have been
//     generated using the sha256 function. The
//     provided hexstring MUST have at least 5
//     hexadecimal characters (20 binary
//     digits). 
// PARAMETER USAGE:
//     hexstring : The hexstring to modulo
//     mod       : The modulus
// FUNCTION CALLED:
//     substr(), size(), stoi()
// RETURNS:
//     The calculated index to hash the hestring
//     to (this could be the index in the RBF or
//     the row index, depending on the value of
//     mod). 
// ---------------------------------------------
int RBF::hashMod(std::string hexstring, int mod) {
  std::string last5 = hexstring.substr(hexstring.size() - 5);
  return (std::stoi(last5, nullptr, 16) % mod);
}

// ---------------------------------------------
// FUNCTION void RBF::fillFilter()
//     Fills the RBF with the malicious IP
//     addresses specificied in the project
//     description.
// PRECONDITION:
//     The RBF SHOULD have a large enough m to
//     reasonably avoid collisions. The RBF
//     MUST have been initialized in some way
//     such that filter is not the nullptr.
// POSTCONDITION:
//     The RBF will now be full of the malicious
//     IP addresses and MAY be used to check
//     those IP addresses. With the checkFilter
//     function.
// FUNCTIONS CALLED:
//     std::to_string(), sha256(), hashMod()
// ---------------------------------------------
void RBF::fillFilter() {
  std::string base = "192.168.";

  // Using the base "192.168.", generated the rest
  // of the malicious addresses
  for (int i = 0; i < 10; i++) {
    // "192.168.i."
    std::string x = base + std::to_string(i) + ".";
    for (int j = 0; j < 10; j++) {
      // "192.168.i.x"
      std::string jbase = x + std::to_string(j);
      for (int k = 0; k < 10; k++) {
	// "192.168.i.xk"
	std::string kbase = jbase + std::to_string(k);
	for (int l = 0; l < 10; l++) {
	  // "192.168.i.xkl"
	  std::string ip = kbase + std::to_string(l);

	  // Generate key=1, 2, .., 8 hashes
	  // Determine H(0||inp) = {0, 1}
	  for (int key = 1; key < 9; key++) {
	    std::string firstHash = sha256(std::to_string(key) + ip);
	    int h = hashMod(firstHash, m);
	    
	    // Assume our 1D array is row 0, then
	    // if H is 0:
	    //     The value of the filter at the index h in row 0 should be true
	    //     => The value of filter[h] = true
	    // if H is 1:
	    //     The value of the filter at the index h in row 1 should be true
	    //     => The value of the filter at the index h in row 0 should be false
	    //     => The value of filter[h] = false
	    std::string secondHash = sha256("0" + std::to_string(h));
	    int H = hashMod(secondHash, 2);
	    if (H == 0) {
	      filter[h] = true;
	    }
	    else {
	      filter[h] = false;
	    }
	  }
	}
      }
    }
  }
}

// ---------------------------------------------
// FUNCTION bool RBF::checkFilter(std::string)
//     Checks whether a provided string has
//     been inserted into the RBF.
// PRECONDITION:
//     The RBF MUST have been initialized.
//     The RBF SHOULD have been filled with
//     malicious IP addresses, either by
//     calling fillFilter() or loadFilter()
// PARAMETERS:
//     ip : The string value of the ip that we
//          want to check against the filter.
//          ("IP" in form xxx.xxx.x.xxx")
// FUNCTIONS CALLED:
//     sha256(), hashMod()
// RETURNS:
//     True if the provided string is in the
//     RBF. False in all other cases.
// ---------------------------------------------
bool RBF::checkFilter(std::string ip) {
  for (int key = 1; key < 9; key++) {
    std::string firstHash = sha256(std::to_string(key) + ip);
    int h = hashMod(firstHash, m);
    std::string secondHash = sha256("0" + std::to_string(h));
    int H = hashMod(secondHash, 2);

    // Filter only stores row 0 of our RBF
    // If H is 0:
    //    If filter[h] is false, then this hash
    //    was never inserted into the bloom filter.
    //    => The string could not have been
    //       inserted into the bloom filter.
    //    Else if filter[h] is true, then this
    //    hash was inserted into the bloom filter,
    //    so the string MAY have been inserted into
    //    the bloom filter, but we must keep
    //    checking the hashes to find out.
    // Else if H is 1:
    //    The same as above, but reverse, i.e.,
    //    If filter[h] is true, then this hash
    //    was never inserted into the bloom filter.
    // If all k=8 hashes have been inserted into
    // the bloom filter, then we return true saying
    // that this string was inserted into the bloom
    // filter.
    if (H == 0) {
      if (filter[h] == false) {
	return false;
      }
    }
    else {
      if (filter[h] == true) {
	return false;
      }
    }
  }

  // All k=8 hashes were found, so we believe this string
  // has been inserted into the bloom filter. 
  return true;
}

// ---------------------------------------------
// FUNCTION void RBF::printFilter(std::fstream)
//     Prints the contents of the bloom filter
//     to an fstream.
// PRECONDITION:
//     The RBF MUST have been initialized.
//     The RBF SHOULD have been filled with
//     malicious IP addresses, either by
//     calling fillFilter() or loadFilter().
// POSTCONDITION:
//     The fstream MAY be used to load the
//     filter into another RBF object using
//     the loadFilter() function. 
// PARAMETERS:
//     ostr : The fstream to print the filter
//            to.
// ---------------------------------------------
void RBF::printFilter(std::fstream &ostr) {
  for (int i = 0; i < m; i++) {
    ostr << filter[i];
  }
}

// ---------------------------------------------
// FUNCTION void RBF::loadFilter(std::fstream)
//     Loads the contents of an fstream into
//     the bloom filter.
// PRECONDITION:
//     The RBF MUST have been initialized.
//     The RBF MAY have been filled with
//     malicious IP addresses, either by
//     calling fillFilter() or loadFilter().
// POSTCONDITION:
//     The RBF will now be full of the malicious
//     IP addresses and MAY be used to check
//     those IP addresses. With the checkFilter
//     function. 
// PARAMETERS:
//     ostr : The fstream to load the filter
//            from. This fstream MUST be a
//            sequence of 0s and 1s (i.e., a
//            sequence of chars representing
//            binary bits). 
// ---------------------------------------------
void RBF::loadFilter(std::fstream &ostr) {
  // This function uses the doubling technique
  // for storing an uncertain amount of data
  // into a dynamic array. While not the most
  // efficient technique, it does work for
  // our purposes.
  char c;
  int i = 0;
  m = 2;
  bool *newFilter = new bool[m];

  // Read the fstream until there is no data left
  // Fill the RBF from left to right, copying 0s
  // as false and 1s as true. If the RBF space is
  // maxed, double the space and copy the data over.
  while ((ostr.get(c), ostr.eof()) == false) {
    if (c == '0') {
      newFilter[i] = false;
    }
    else {
      newFilter[i] = true;
    }
    i++;

    // Resize RBF as necessary
    if (i == m) {
      m *= 2;
      bool *tempFilter = new bool[m];
      for (int j = 0; j < i; j++) {
	tempFilter[j] = newFilter[j];
      }
      delete [] newFilter;
      newFilter = tempFilter;
    }
  }

  // Resize the array to the exact value of i
  bool *tempFilter = new bool[i];
  for (int j = 0; j < i; j++) {
    tempFilter[j] = newFilter[j];
  }

  // Clean up memory and reassign our filter
  // i is the exact value of m
  delete [] filter;
  delete [] newFilter;
  filter = tempFilter;
  m = i;
}
