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
void Encryption(int m, epoint* pk,epoint *G,epoint *OutC1,epoint*OutC2,uint32_t *OutC3)//加密前，一定要要设置Active Curve
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
    bigbits(255, k);//生成随机数K
    ecurve_mult(k, G, c1);//计算密文c1=k*G
    /*********************************C1密文计算**************************************************/
    RuntimeLogger->info("C1 calculation complete");
    ecurve_mult(k, pk, X2Y2);//计算点(X2,Y2)=k*pk
    epoint_copy(X2Y2, ToxicWaste);
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
    /*********************************C2密文计算**************************************************/
    RuntimeLogger->info("C2 calculation complete");
    epoint_free(ToxicWaste);
    RuntimeLogger->info("Start C3 calculatioin");
    /*********************************C3密文计算**************************************************/
    epoint_get(X2Y2, x2, y2);
    big_to_bytes(32, x2, (char*)X2, RightJustify);
    big_to_bytes(32, y2, (char*)Y2, RightJustify);
    for (int i = 0; i < 32; i++)
        HashInput[i] = X2[i];
    HashInput[33] = (u8)m;
    for (int i = 33; i < 65; i++)
        HashInput[i] = Y2[i - 33];
    Sm3_1024(HashInput, 520);
    for (int i = 0; i < 8; i++)
        C3[i] = SM3_hash_result[i];
    /*********************************C3密文计算**************************************************/
    RuntimeLogger->info("C3 calculation complete");
    /*********************************返回结果**************************************************/
    epoint_copy(OutC1, c1);
    epoint_copy(OutC2, c2);
    OutC3 = C3;
    RuntimeLogger->info("Result Returned");
    /*********************************释放空间**************************************************/
    epoint_free(c1);
    epoint_free(c2);
    epoint_free(X2Y2);
    RuntimeLogger->info("Heap Space Free Complete");
}
