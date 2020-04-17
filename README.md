# libPSI
A repository for private set intersection. Most protocols were written just for benchmarking them while (RR17,KKRT,Mea86=ECDH) can be run from the command line and take a file as input. Run the program for details.


## Introduction
Protocols:

 * Malicious Secure [RR17](https://eprint.iacr.org/2017/769) based on simple hashing and OTs (fastest)
 * Malicious Secure [RR16](https://eprint.iacr.org/2016/746) based on Bloom filters and OTs
 * Malicious Secure [DKT10](https://eprint.iacr.org/2010/469) based on public key crypto (ECC)
 * Semi-Honest Secure [KKRT16](https://eprint.iacr.org/2016/799) based on cuckoo hashing and OTs (fastest)
 * Semi-Honest Secure [Mea86](http://ieeexplore.ieee.org/document/6234849/) base on public key crypto (ECC)
 * Semi-Honest Secure [DRRT18](https://eprint.iacr.org/2018/579.pdf) based on cuckoo hashing, PIR and OTs (fastest unbalanced)
 
## Install

Our library is cross platform and has been tested on both Windows and Linux. The library should work on Mac but it has not been tested. There are several library dependencies including [libOTe](https://github.com/osu-crypto/libOte), Boost, Miracl. First follow the instructions at libOTe. 


### Windows

First clone and build libOTe. libOTe and libPSI should share the same parent directory. Then clone this library and open the solution in Visaul Studio.

### Linux


libOTe and libPSI should share the same parent directory.

```
[libOTe clone build steps](https://github.com/osu-crypto/libOTe)
git clone https://github.com/osu-crypto/libPSI.git
cd libPSI
cmake . -DENABLE_XXXX=ON
make
```
here, `-DENABLE_XXXX` should refer to the public key library used with libOTe, i.e. `-DENABLE_RELIC`, `-DENABLE_MIRACL`, or `-DENABLE_SIMPLESTOT_ASM`. 


Unit tests can be run by executing the program.

```
./bin/frontend.exe -u
```
Other options can be seen by executing with no arguments.
## Help

Contact Peter Rindal `peterrindal@gmail.com` for any assistance on building or running the library.
