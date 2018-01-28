#include "cryptoTools/Common/Log.h"
#include <functional>

#include "AknBfPsi_Tests.h"
//#include "nkOt_Tests.h"
//#include "BaseOT_Tests.h"
//#include "OT_Tests.h"
//#include "NcoOT_Tests.h"
#include "AknBfPsi_Tests.h"
#include "BinOtPsi_Tests.h"

#include "ShamirSSScheme_Tests.h"
#include "DcwBfPsi_Tests.h"
#include "DktMPsi_Tests.h"

using namespace osuCrypto;

void run(std::string name, std::function<void(void)> func)
{
    std::cout << name;
    std::cout << std::flush;
    auto start = std::chrono::high_resolution_clock::now();
    try
    {
        func(); std::cout << Color::Green << "  Passed" << ColorDefault;
    }
    catch (const std::exception& e)
    {
        std::cout << Color::Red << "Failed - " << e.what() << ColorDefault;
    }

    auto end = std::chrono::high_resolution_clock::now();

    u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "   " << time << "ms" << std::endl;


}


void kkrt_psi_all()
{
    std::cout << std::endl;
    run("Psi_kkrt_EmptySet_Test_Impl         ", Psi_kkrt_EmptySet_Test_Impl);
    run("Psi_kkrt_FullSet_Test_Impl           ", Psi_kkrt_FullSet_Test_Impl);
    run("Psi_kkrt_SingletonSet_Test_Impl       ", Psi_kkrt_SingletonSet_Test_Impl);

}


void DktPsi_all()
{ 
    //std::cout << std::endl;
    //run("DktPsi_EmptrySet_Test_Impl              ", DktMPsi_EmptrySet_Test_Impl);
    //run("DktPsi_FullSet_Test_Impl                ", DktMPsi_FullSet_Test_Impl);
    //run("DktPsi_SingltonSet_Test_Imp             ", DktMPsi_SingltonSet_Test_Impl);
}

#ifdef ENABLE_DCW
void DcwPsi_all()
{
    std::cout << std::endl;
    run("DcwPsi_EmptrySet_Test_Impl              ", DcwBfPsi_EmptrySet_Test_Impl);
    run("DcwPsi_FullSet_Test_Impl                ", DcwBfPsi_FullSet_Test_Impl);
    run("DcwPsi_SingltonSet_Test_Imp             ", DcwBfPsi_SingltonSet_Test_Impl);
}
void ShamirSSScheme_all()
{
    std::cout << std::endl;
    run("ShamirSSScheme_GF2X_Test                 ", ShamirSSScheme_Test);
}
#endif
void AknBfPsi_all()
{
    std::cout << std::endl;
    run("RR16_EmptrySet_Test_Impl            ", AknBfPsi_EmptrySet_Test_Impl);
    run("RR16_FullSet_Test_Impl              ", AknBfPsi_FullSet_Test_Impl);
    run("RR16_SingltonSet_Test_Impl          ", AknBfPsi_SingltonSet_Test_Impl);
}
void OtBinPsi_all()
{
    std::cout << std::endl;
    run("CuckooHasher_Test_Impl          ", CuckooHasher_Test_Impl);

    run("Rr17a_Oos_EmptrySet_Test_Impl         ", Rr17a_Oos_EmptrySet_Test_Impl);
    run("Rr17a_Oos_FullSet_Test_Impl           ", Rr17a_Oos_FullSet_Test_Impl);
    run("Rr17a_Oos_SingltonSet_Test_Impl       ", Rr17a_Oos_SingltonSet_Test_Impl);

    run("Rr17b_Oos_EmptrySet_Test_Impl         ", Rr17b_Oos_EmptrySet_Test_Impl);
    run("Rr17b_Oos_FullSet_Test_Impl           ", Rr17b_Oos_FullSet_Test_Impl);
    run("Rr17b_Oos_SingltonSet_Test_Impl       ", Rr17b_Oos_SingltonSet_Test_Impl);

}




void run_all()
{
    //LinearCode_Test_Impl();
    //run("OosNcoOt_Test_Impl                      ", OosNcoOt_Test_Impl);
    //run("KkrtNcoOt_Test                          ", KkrtNcoOt_Test_Impl);
    //run("Rr17a_Oos_SingltonSet_Test_Impl       ", Rr17a_Oos_SingltonSet_Test_Impl);

    //run("Rr17a_Kkrt_SingltonSet_Test_Impl      ", Rr17a_Kkrt_SingltonSet_Test_Impl);
    //NetWork_all();
    //bitVec_all();
    //Ecc_all();
    //OT_all();
    kkrt_psi_all();
    AknBfPsi_all();
    OtBinPsi_all();
    //DcwPsi_all();
    DktPsi_all();
}
