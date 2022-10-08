extern "C"
{
#include<stdio.h>
#include"miracl.h"
#include<time.h>
}
#include<iostream>
#include"SM2_Param.h"
#include"sm3.h"
#include"include/spdlog/spdlog.h"
#include "include/spdlog/sinks/basic_file_sink.h"
#include "include/spdlog/sinks/rotating_file_sink.h"
#include<time.h>
using namespace spdlog;
/*****************************************Parameters decleration*****************************************/
#define VotePass 1
#define VoteNotPass 0
#define PkCheckPass 1
#define PkCheckFailed 0
#define MaxBitLength 64
#define RightJustify 1
#define LeftJustify 0
#define PointInfinite 2
#define HexIOBASAE 16
#define PointNotOnCurve 3
#define DecryptionFail 4
#define HashValueError 5
auto RuntimeLogger = spdlog::basic_logger_mt("basic_logger", "logs/RunTimeLog.txt");
typedef uint8_t u8;
/*****************************************Parameters decleration*****************************************/
void PrintErrorMessage(int Error)
{
    switch (Error)
    {
    case PointInfinite:
    {
        printf("Curve Point is Infinite\n");
        return;
    }
    case PointNotOnCurve:
    {
        printf("Point is not on the current active curve\n");
        return;
    }
    case DecryptionFail:
    {
        printf("Decryption failed for unknown reason\n");
        return;
    }
    case HashValueError:
    {
        printf("Decryption failed for hash value error\n");
        return;
    }
    }
}
bool CheckCurvePointInfinite(epoint* pk)//check if the public key is valid
{
    bool Flag1 = 0;
    bool Flag2 = 0;
    if (pk == NULL)
    {
        RuntimeLogger->error("Point Infinite!");
        throw PointInfinite;
    }
    else
    {
        big x, y;
        x = mirvar(0);
        y = mirvar(0);
        epoint_get(pk, x, y);
        u8* Bytes_x = (u8*)malloc(MaxBitLength * sizeof(u8));
        u8* Bytes_y = (u8*)malloc(MaxBitLength * sizeof(u8));
        memset(Bytes_x, 0, MaxBitLength);
        memset(Bytes_y, 0, MaxBitLength);
        int Lsb = epoint_get(pk, x, y);
        int Length_x = big_to_bytes(MaxBitLength, x, (char*)Bytes_x, RightJustify);
        int Length_y = big_to_bytes(MaxBitLength, y, (char*)Bytes_y, RightJustify);
        for (int i = 0; i < MaxBitLength; i++)
        {
            if ((int)Bytes_x[i] != 0)
            {
                Flag1 = 1;
                break;
            }
        }
        for (int i = 0; i < 64; i++)
        {
            if ((int)Bytes_y[i] != 0)
            {
                Flag2 = 1;
                break;
            }
        }
        free(Bytes_x);
        free(Bytes_y);
        return Flag1 && Flag2;
    }
}
void epoint_print(epoint* point)
{
    big x, y;
    x = mirvar(0);
    y = mirvar(0);
    epoint_get(point, x, y);
    cotnum(x, stdout);
    cotnum(y, stdout);
}
void print_hash(uint32_t *HashOutput)
{
    for (int i = 0; i < 8; i++)
    {
        
        printf("%x ", HashOutput[i]);
    }
    printf("\n");
}
void Encryption(int m, epoint* pk,epoint *G,epoint *OutC1,epoint*OutC2,uint32_t *OutC3,char* kout)//加密前，一定要要设置Active Curve
{
    RuntimeLogger->info("Encryption Start");
    RuntimeLogger->info("Public Key Validity Check");
    try
    {
        bool PkValid = CheckCurvePointInfinite(pk);
    }
    catch (int error)
    {
        PrintErrorMessage(error);
    }
    big h, k, x2, y2;
    epoint* S, * c1, * X2Y2, * c2, * ToxicWaste;
    u8* X2, * Y2, * HashInput;
    uint32_t* C3;
    X2 = (u8*)malloc(32 * sizeof(u8));
    Y2 = (u8*)malloc(32 * sizeof(u8));
    HashInput = (u8*)malloc(65 * sizeof(u8));
    C3 = (uint32_t*)malloc((8) * sizeof(uint32_t));
    h = mirvar(1);
    k = mirvar(0);
    x2 = mirvar(0);
    y2 = mirvar(0);
    c1 = epoint_init();
    S = epoint_init();
    X2Y2 = epoint_init();
    c2 = epoint_init();
    ToxicWaste = epoint_init();
    //epoint_set()
    ecurve_mult(h, S, S);
    RuntimeLogger->info("Public Key Validity Check Pass,encryption parameters init succeed!");
    try
    {
        bool S_valid = CheckCurvePointInfinite(S);
    }
    catch (int error)
    {
        PrintErrorMessage(error);
    }
    epoint_free(S);//epoint在heap上分配空间，废弃参数请立即销毁

    RuntimeLogger->info("Start C1 calculatioin");
    /*********************************C1密文计算**************************************************/
    bigbits(256, k);//生成随机数K
    char* temp = (char*)malloc(32 * sizeof(char));
    big_to_bytes(32, k, temp, RightJustify);
    memcpy(kout, temp, 32);
    //big_to_bytes()
    ecurve_mult(k, G, c1);//计算密文c1=k*G
    //epoint_print(c1);
    //epoint_print(c1);
    /*********************************C1密文计算**************************************************/
    RuntimeLogger->info("C1 calculation complete");
    ecurve_mult(k, pk, X2Y2);//计算点(X2,Y2)=k*pk
    //epoint_print(X2Y2);
    epoint_get(X2Y2, x2, y2);
    big_to_bytes(32, x2, (char*)X2, RightJustify);
    big_to_bytes(32, y2, (char*)Y2, RightJustify);
    //epoint_print(X2Y2);
    epoint_copy(X2Y2, ToxicWaste);
    //epoint_print(X2Y2);
    RuntimeLogger->info("Start C2 calculatioin");
    /*********************************C2密文计算**************************************************/
    if (m == 0)
    {
        ecurve_add(G, ToxicWaste);//ToxicWaste的值就是X2Y2的值，这样做是为了防范侧信道攻击,保证计算量一致
        epoint_copy(X2Y2, c2);
    }
    else if (m == 1)
    {
        ecurve_add(G, X2Y2);
        epoint_copy(X2Y2, c2);
    }
    //epoint_print(c2);
    /*********************************C2密文计算**************************************************/
    RuntimeLogger->info("C2 calculation complete");
    epoint_free(ToxicWaste);
    RuntimeLogger->info("Start C3 calculatioin");
    /*********************************C3密文计算**************************************************/
    for (int i = 0; i < 32; i++)
        HashInput[i] = X2[i];
    HashInput[32] = 1;
    for (int i = 33; i < 65; i++)
        HashInput[i] = Y2[i - 33];
    for (int i = 0; i < 65; i++)
    {
        printf("%x", HashInput[i]);
    }
    printf("\n");
    Sm3_1024(HashInput, 520);
    print_hash(SM3_hash_result);
    for (int i = 0; i < 8; i++)
        OutC3[i] = SM3_hash_result[i];
    /*********************************C3密文计算**************************************************/
    RuntimeLogger->info("C3 calculation complete");
    /*********************************返回结果**************************************************/
    epoint_copy(c1, OutC1);
    epoint_copy(c2, OutC2);
    RuntimeLogger->info("Result Returned");
    /*********************************释放空间**************************************************/
    epoint_free(c1);
    epoint_free(c2);
    epoint_free(X2Y2);
    RuntimeLogger->info("Heap Space Free Complete");
}
int Decryption(epoint* c1, epoint* c2,epoint*G, uint32_t* c3, big sk)
{

    big x2, y2;
    u8* X2, * Y2, * HashInput;
    uint32_t* u = (uint32_t*)malloc(8 * sizeof(uint32_t));
    X2 = (u8*)malloc(32 * sizeof(u8));
    Y2 = (u8*)malloc(32 * sizeof(u8));
    HashInput = (u8*)malloc(65 * sizeof(u8));
    x2 = mirvar(0);
    y2 = mirvar(0);
    if (point_at_infinity(c1) || point_at_infinity(c2))
    {
        RuntimeLogger->error("C1 or C2 is at infinity");
        return -1;
    }
    big x = mirvar(0);
    big y = mirvar(0);
    epoint_get(c1, x, y);
    if (!epoint_x(x))
    {
        RuntimeLogger->error("C1 is not on the curve");
        throw PointNotOnCurve;
        return -1;
    }
    epoint* X2Y2, * mG;
    X2Y2 = epoint_init();
    mG = epoint_init();
    //epoint_print(c1);
    //cotnum(sk,stdout);
    ecurve_mult(sk, c1, X2Y2);
    epoint_get(X2Y2, x2, y2);
    
    //epoint_print(X2Y2);
    big_to_bytes(32, x2, (char*)X2, RightJustify);
    big_to_bytes(32, y2, (char*)Y2, RightJustify);
    printf("\n");
    ecurve_sub(X2Y2, c2);
    epoint_copy(c2, mG);
    if (point_at_infinity(c2))
    {
        return 0;
    }
    if (epoint_comp(G, mG))
    {
        for (int i = 0; i < 32; i++)
        {
            HashInput[i] = X2[i];
        }
        HashInput[32] = 1;
        for (int i = 33; i < 65; i++)
        {
            HashInput[i] = Y2[i - 33];
        }
        
        Sm3_1024(HashInput, 520);
        
        for (int i = 0; i < 8; i++)
        {
            if (SM3_hash_result[i] != c3[i])
            {
                printf("%x %x\n", SM3_hash_result[i],c3[i]);
                RuntimeLogger->error("Decryption failed for hash value error");
                throw HashValueError;
            }
        }
        return 1;
        RuntimeLogger->info("Decryption Complete");
    }
    RuntimeLogger->error("Decryption Bad Parameters");
    throw DecryptionFail;
}