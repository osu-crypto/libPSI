#pragma once



#ifdef ENABLE_DCW


#include "util.h"


#include <vector> 
#include "cryptoTools/Common/Defines.h"

void DcwSend(LaunchParams&);
void DcwRecv(LaunchParams&);



void DcwRSend(LaunchParams&);
void DcwRRecv(LaunchParams&);


#endif