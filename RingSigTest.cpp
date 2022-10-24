extern "C"
{
#include"miracl.h"
#include"mirdef.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>
}
#include"SM3acl.h"
#include"SM2RingSig.h"
int main()
{
    miracl* mip = mirsys(36, MAXBASE);
    time_t seed;
    time(&seed);
    irand((unsigned long long)seed);
    int plaintext = 1;
    int cb = 0;
    mip->IOBASE = HexIOBASAE;
    big sk, k, a, b, p, g_x, g_y, c1_x_big, c1_y_big, c2_x_big, c2_y_big, q, SkByShare;
    epoint* pk, * G, * c1, * c2;
    uint32_t* c3;
    uint8_t* c1_x, * c1_y, * c2_x, * c2_y;
    SkByShare = mirvar(0);
    sk = mirvar(0);
    k = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    p = mirvar(0);
    g_x = mirvar(0);
    g_y = mirvar(0);
    k = mirvar(0);
    q = mirvar(0);
    c1_x_big = mirvar(0);
    c1_y_big = mirvar(0);
    c2_x_big = mirvar(0);
    c2_y_big = mirvar(0);
    big pk_x, pk_y;
    pk_x = mirvar(0);
    pk_y = mirvar(0);
    bytes_to_big(32, TempSK, sk);
    bytes_to_big(32, Sm2CurveParamG_x, g_x);
    bytes_to_big(32, Sm2CurveParamG_y, g_y);
    bytes_to_big(32, Sm2CurveParam_a, a);
    bytes_to_big(32, Sm2CurveParam_b, b);
    bytes_to_big(32, Sm2CurveParamPrime, p);
    bytes_to_big(32, Sm2CurveParamG_Order, q);
    bytes_to_big(32, TempPK_X, pk_x);
    bytes_to_big(32, TempPK_Y, pk_y);
    ecurve_init(a, b, p, MR_BEST);
    G = epoint_init();
    epoint_set(g_x, g_y, 1, G);
    
    //printf("¹«Ô¿¼¯£º\n");
    const int Mlength = 14;
    uint8_t M[Mlength]{ 0x12,0x23,0x18,0x92,0xd9,0xa9,0xdd,0xc9,0x1a,0xdc,0xac,0xbd,0x1d,0xaa };
    const int m = 200;
    int L = 50;
    point* PK = (point*)malloc(m * sizeof(point));
    for (int i = 0; i < m; i++)
    {
        PK[i] = epoint_init();
        bigbits(255, k);
        ecurve_mult(k, G, PK[i]);
        //epoint_print(PK[i]);
    }
    
    uint8_t* Lhash = (uint8_t*)malloc(32 * sizeof(uint8_t));
    uint8_t* BL1BL2 = (uint8_t*)malloc(96 * sizeof(uint8_t));
    uint8_t* BL = (uint8_t*)malloc(128 * sizeof(uint8_t));
    uint8_t* Bl_12 = (uint8_t*)malloc(32 * sizeof(uint8_t));
    uint8_t** ai = (uint8_t**)malloc(m * sizeof(uint8_t*));
    for (int i = 0; i < m; i++)
        ai[i] = (uint8_t*)malloc(32 * sizeof(uint8_t));
    for (int i = 0; i < m; i++)
    {
        for (int j = 0; j < 32; j++)
            ai[i][j] = 0;
    }
    

    big KL = mirvar(0);
    
    for (int i = 0; i < 10; i++)//²âÊÔÉú³ÉÊ®´Î
    {
        KL = SM2RingSigGen(G, PK, sk, BL, ai, M, m, L, Mlength, Lhash);
        printf("BL:\n");
        Align8Print(BL, 128);
        printf("AL:\n");
        for (int i = 0; i < m; i++)
        {
            printf("a%d:\n", (i + 1));
            Align8Print(ai[i], 32);
        }
        printf("KL:\n");
        cotnum(k, stdout);
        printf("\n\n\n");
        SM2RingSigProof(G, PK, BL, ai, M, m, L, Mlength, KL);
    }
}
