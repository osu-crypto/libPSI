# libPSI
A repository for private set intersection. Companion paper under submission.

## Introduction

Primary construction is malicious secure and is based on the Garbled Bloom Filter construction of DCW. We implement an improved construction and note that the original DCW construction has a bug which is fixed in this work. The primary construction is embodied in the class AknBfPsi\*. The DcwPsi\* protools were implemented for comparison perposes and should not be used (insecure and slow).


## Install

Oour library is cross platform and has been tested on both Windows and Linus. The library should work on MAC but it has not been tested. There are several library dependancies including Boost, Crypto++, Miracl, Mpir, NTL.

### Windows

Once cloned, the libraries listed above must be built. For Boost, Crypto++, Miracl, Mpir there are powershell scripts that download and build the libraries. NTL there is a script that downloads it but not build it. Building can be done maually using VS or the method specified in their read me.

Unit tests are built into the Test explorer and should all be passing. The front end can also run the unit tests.


### Linux

Once cloned, the libraries listed above must be built. In Thirdparty/linux there are scripts that will download and build all of the libraries that are listed above. 

Unit tests can be run by executing the program with no arguments.

## Help

Contact Peter Rindal rindalp@oregonstate.edu for any assistance on building or running the library.



