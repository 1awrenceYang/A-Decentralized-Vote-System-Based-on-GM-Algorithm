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
    int m = 1;
    int m1 = 1;
    Encryption(m, pk, G, c1, c2, c3);
    //big kk = mirvar(0);
    //bytes_to_big(32, k1, kk);
    
    printf("-------------------------First Encryption Complete-----------------------------\n");
    printf("C1 ciphertext:\n");
    epoint_print(c1);
    printf("C2 ciphertext:\n");
    epoint_print(c2);
    printf("C3 ciphertext:\n");
    print_hash(c3);
    printf("plaintext:\n");
    printf("%d\n\n\n", m);
    //epoint_print(c1);
    //epoint_print(c2);
    //print_hash(c3);
    int i = 0;
    /*try
    {
        i = Decryption(c1, c2, G, c3, sk);
        printf("plaintext:%d\n", i);
        printf("-------------------------First Decryption Complete-----------------------------\n");
        
        
    }
    catch (int error)
    {
        PrintErrorMessage(error);
    }*/
    printf("\n\n\n");
    
    epoint* c11, * c22;
    uint32_t* c33;
    c11 = epoint_init();
    c22 = epoint_init();
    c33 = (uint32_t*)malloc(8 * sizeof(uint32_t));
    Encryption(m1, pk, G, c11, c22, c33);
    printf("-------------------------Second Encryption Complete-----------------------------\n");
    printf("C1 ciphertext:\n");
    epoint_print(c11);
    printf("C2 ciphertext:\n");
    epoint_print(c22);
    printf("C3 ciphertext:\n");
    print_hash(c33);
    printf("plaintext:\n");
    printf("%d\n\n\n", m1);
    /*int m2=Decryption(c11, c22, G, c33, sk);
    printf("Decryption plaintext result:\n");
    printf("%d", m2);*/
    epoint* HomoC1, * HomoC2;
    HomoC1 = epoint_init();
    HomoC2 = epoint_init();
    HomoEncryption(c1, c11, c2, c22, HomoC1, HomoC2);
    //HomoEncryption(HomoC1, c1, HomoC2, c2, HomoC1, HomoC2);
    printf("Homo C1 Ciphertext:\n");
    epoint_print(HomoC1);
    printf("Homo C2 Ciphertext:\n");
    epoint_print(HomoC2);

    try
    {
        int m2 = 0;
        HomoDecryption(HomoC1, HomoC2, G, sk, &m2);
        printf("HomoDecryption result:\n");
        printf("%x", m2);
    }
    catch (int error)
    {
        PrintErrorMessage(error);
    }
}
