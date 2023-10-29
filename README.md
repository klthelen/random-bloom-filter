# random-bloom-filter

Please note that the SHA256 function has been found online as the specification allowed.
The SHA256 code can be found at http://www.zedwood.com/article/cpp-sha256-function

From the /source folder, the two executables RBFGen and IPCheck can be compiled with:<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`make all`<br/>

All objects and binaries can be removed with: </br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`make clean`

# Testing 

You can test the program as follows:
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`./RBFGen <m>`
     	   
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`./IPCheck <file.txt> <ip address xxx.xxx.x.xxx>`
 
Where m is the calculated minimum length (i.e., column number) for the RBF using the formula m = -kn/ln(1-P^(1/k)) and file.txt is the generated RBF file from RBFGen.

This implementation automatically assumes that all IP addresses in the form of 192.168.X.XXX are malicious (10,000 IP addresses). 

The program will output `pass` if the IP address is not found in the bloom filter or `block` if it is found in the bloom filter (i.e., if it is an IP address in the form of 192.168.X.XXX). 

# Example
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`./RBFGen 210455`
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`./IPCheck RBFRow1.txt 192.168.2.222`

While the program checks for the correct number of inputs, it will not properly
handle inputs of the wrong type (e.g., inputting a string for m), so please test
it like the above.

# Questions

#### (a) If the false positive rate of the RBF should be less than 0.01%, please determine the minimum length of the used RBF m1. For an IP address, assume that it has 13 chars. For each RBF suppose that only one row is required to be stored. Each cell only requires 1 bit space. Please compute the space compression factor c1=(space cost using a list)/(space cost using an RBF)

	k = 8, n = 10000, P = 0.0001
	m = -kn/ln(1-P^(1/k))
  	=> m = -8*10000/ln(1-0.0001^(1/8))
  	=> m = 210454.09233
  	=> m1 = 210455

	space cost using a list = 13 chars * 10000 inputs = 130000 byte space
	      	   	   	=> 130000 byte space * 8 = 1040000 bit space
	space cost using RBF = 1 char * 210455 inputs = 210455 bit space
	c1 = 1040000/210455 = 4.94167399206

#### (b) If the false positive rate of the RBF should be less than 0.1%, please determine the minimum length of the used RBF m2 and the space compression factor c2.

	k = 8, n = 10000, p = 0.001
	m = -kn/ln(1-P^(1/k))
	=> m = -8*10000/ln(1-0.001^(1/8))
	=> m = 146076.97478
	=> m2 = 146077

	space cost using a list = 13 chars * 10000 inputs = 130000 bit space
	      	   	   	=> 130000 byte space * 8 = 1040000 bit space
	space cost using RBF = 1 char * 146077 inputs = 146077 bit space
	c2 = 1040000/146077 = 7.11953284911
