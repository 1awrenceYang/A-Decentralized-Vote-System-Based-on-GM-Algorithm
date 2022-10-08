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
   /* miracl* mip = mirsys(36, MAXBASE);
    big a, b, p, pk, sk;
    a = mirvar(0);
    b = mirvar(0);
    p = mirvar(0);
    pk = mirvar(0);
    sk = mirvar(0);*/
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
    /*uint8_t wait[65] = { 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
                          0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
                          0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
                          0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64 ,0x61 };
    Sm3_1024(wait, 520);*/
    miracl* mip = mirsys(36, MAXBASE);
    time_t seed;
    time(&seed);
    irand((unsigned long long)seed);
    
    int plaintext = 1;
    int cb = 0;
    mip->IOBASE = HexIOBASAE;
    big sk, k, a, b, p, g_x, g_y, c1_x_big, c1_y_big, c2_x_big, c2_y_big;
    epoint* pk, * G, * c1, * c2;
    uint32_t* c3;
    uint8_t* c1_x, *c1_y, *c2_x, *c2_y;
    sk = mirvar(0);
    k = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    p = mirvar(0);
    g_x = mirvar(0);
    g_y = mirvar(0);
    k = mirvar(0);
    //kout = mirvar(0);
    c1_x_big = mirvar(0);
    c1_y_big = mirvar(0);
    c2_x_big = mirvar(0);
    c2_y_big = mirvar(0);
    bigbits(256, sk);
    //cotnum(sk,stdout);
    bytes_to_big(32, Sm2CurveParamG_x, g_x);
    bytes_to_big(32, Sm2CurveParamG_y, g_y);
    bytes_to_big(32, Sm2CurveParam_a, a);
    bytes_to_big(32, Sm2CurveParam_b, b);
    bytes_to_big(32, Sm2CurveParamPrime, p);
    G = epoint_init();
    pk = epoint_init();
    c1 = epoint_init();
    c2 = epoint_init();
    c3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
    c1_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
    c1_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
    c2_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
    c2_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
    ecurve_init(a, b, p, MR_BEST);
    epoint_set(g_x, g_y, cb, G);
    ecurve_mult(sk, G, pk);
    char* k1 = (char*)malloc(32 * sizeof(char));
    //cotnum(sk, stdout);
    Encryption(1, pk, G, c1, c2, c3, k1);
    big kk = mirvar(0);
    bytes_to_big(32, k1, kk);
    
    //epoint_print(c1);
    //epoint_print(c2);
    //print_hash(c3);
    int i = 0;
    try
    {
        i = Decryption(c1, c2, G, c3, sk);
        printf("\n\n\n%d", i);
    }
    catch (int error)
    {
        PrintErrorMessage(error);
    }
    printf("\n\n\n");
    bigbits(256, k);
    epoint* t1 = epoint_init();
    epoint* t2 = epoint_init();
    epoint* t3 = epoint_init();
    epoint* t4 = epoint_init();
    ecurve_mult(kk, G, t1);
    ecurve_mult(sk, t1, t2);
    ecurve_mult(sk, G, t3);
    ecurve_mult(kk, t3, t4);
    //epoint_print(t2);
    printf("\n");
   // epoint_print(t4);
}
