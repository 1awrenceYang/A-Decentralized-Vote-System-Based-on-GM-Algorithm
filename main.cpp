#include "SM2.h"
#define LogCreated
int main()
{
    
#ifndef LogCreated
    try
    {
        RuntineLogger->info("Log created!");
    }
    catch (const spdlog::spdlog_ex& ex)
    {
        std::cout << "Log initialization failed: " << ex.what() << std::endl;
    }
#endif
    miracl* mip = mirsys(36, MAXBASE);
    big a, b, p, pk, sk;
    a = mirvar(0);
    b = mirvar(0);
    p = mirvar(0);
    pk = mirvar(0);
    sk = mirvar(0);
    //pk = NULL;
    /*try
    {
        printf("%d", CheckCurvePointInfinite(pk));
    }
    catch (int e)
    {
        PrintErrorMessage(e);
    }*/
    /*u8* Bytes_x = (u8*)malloc(MaxBitLength * sizeof(u8));
    u8* Bytes_y = (u8*)malloc(MaxBitLength * sizeof(u8));
    memset(Bytes_x, 0, MaxBitLength);
    memset(Bytes_y, 0, MaxBitLength);
    int Lsb = epoint_get(pk1, x, y);
    int Length_x = big_to_bytes(MaxBitLength, x, (char*)Bytes_x, RightJustify);
    int Length_y = big_to_bytes(MaxBitLength, y, (char*)Bytes_y, RightJustify);
    for (int i = 0; i < MaxBitLength; i++)
    {
        printf("%x", Bytes_y[i]);
    }*/
    uint8_t wait[65] = { 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
                          0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
                          0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
                          0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64 ,0x61 };
    Sm3_1024(wait, 520);

    int plaintext = 1;





}