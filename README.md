# libPSI
A repository for private set intersection. 


## Introduction
Protocols:

 * Malicious Secure [RR17](https://eprint.iacr.org/2016/746) based on Bloom filters and OTs
 * Malicious Secure [DKT10](https://eprint.iacr.org/2010/469) based on public key crypto (ECC)
 * Semi-Honest Secure [KKRT16](https://eprint.iacr.org/2016/799) based on cuckoo hashing and OTs
 
## Install

Our library is cross platform and has been tested on both Windows and Linux. The library should work on Mac but it has not been tested. There are several library dependencies including [libOTe](https://github.com/osu-crypto/libOte), Boost, Miracl, NTL. First follow the instructions at libOTe. Then build ntl located in `./thirdparty/`. A script is provided.

### Windows

Once cloned, the libraries listed above must be built. Then open the solution in Visaul Studio.

### Linux

Once cloned, the libraries listed above must be built. In Thirdparty/linux there are scripts that will download and build all of the libraries that are listed above. To build the library:

```
cmake -G"Unix Makefiles"
make
```

Unit tests can be run by executing the program.

```
./bin/frontend.exe -u
```
Other options can be seen by executing with no arguments.
## Help

Contact Peter Rindal `rindalp@oregonstate.edu` for any assistance on building or running the library.
