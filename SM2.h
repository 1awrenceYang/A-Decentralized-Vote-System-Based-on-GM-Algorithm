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
#define HomoDecryptionError 6
#define MaxVoteNum 100
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
    case HomoDecryptionError:
    {
        printf("Homo Decryption failed for unknown reason\n");
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
    bigbits(256, k);//生成随机数K
    char* temp = (char*)malloc(32 * sizeof(char));
    big_to_bytes(32, k, temp, RightJustify);
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
    /*for (int i = 0; i < 65; i++)
    {
        printf("%x", HashInput[i]);
    }*/
    printf("\n");
    Sm3_1024(HashInput, 520);
    //print_hash(SM3_hash_result);
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
    printf("C1 ciphertext:\n");
    epoint_print(c1);
    printf("C2 ciphertext:\n");
    epoint_print(c2);
    printf("C3 ciphertext:\n");
    print_hash(c3);
    //FIXME---加入日志以及内存释放！！！！！！！！
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
    if (point_at_infinity(c2))//FIXME!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-----add Hash value check!
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
void HomoEncryption(epoint* c1, epoint* c11, epoint* c2, epoint* c22,epoint*OutC1,epoint*OutC2)
{
    if (point_at_infinity(c1) || point_at_infinity(c11), point_at_infinity(c2) || point_at_infinity(c22))
    {
        RuntimeLogger->error("Homo Encryption failed for point infinity");
        throw PointInfinite;
    }
    big x1, x2, x3, x4, y1, y2, y3, y4;
    x1 = mirvar(0);
    x2 = mirvar(0);
    x3 = mirvar(0);
    x4 = mirvar(0);
    y1 = mirvar(0);
    y2 = mirvar(0);
    y3 = mirvar(0);
    y4 = mirvar(0);
    epoint_get(c1, x1, y1);
    epoint_get(c11, x2, y2);
    epoint_get(c2, x3, y3);
    epoint_get(c22, x4, y4);
    if (!epoint_x(x1) || !epoint_x(x2) || !epoint_x(x3) || !epoint_x(x4))
    {
        RuntimeLogger->error("Homo Encryption failed for point not on curve");
        throw PointNotOnCurve;
    }
    RuntimeLogger->info("Homo Encryption start");
    epoint* temp1, * temp2;
    temp1 = epoint_init();
    temp2 = epoint_init();
    epoint_copy(c11, temp1);//存下原来的密文值
    epoint_copy(c22, temp2);
    ecurve_add(c1, c11);
    ecurve_add(c2, c22);
    RuntimeLogger->info("Homo Encryption complete");
    epoint_copy(c11, OutC1);
    epoint_copy(c22, OutC2);
    epoint_copy(temp1, c11);
    epoint_copy(temp2, c22);
    epoint_free(temp1);
    epoint_free(temp2);
}
void HomoDecryption(epoint* c1, epoint* c2, epoint* G , big sk , int *m)
{
    if (point_at_infinity(c1) || point_at_infinity(c2))
    {
        RuntimeLogger->error("Homo Decryption failed for point infinity");
        throw PointInfinite;
    }
    big x1, x2, y1, y2, r;
    epoint* mG, * temp, * tempC2, * BSGS;
    mG = epoint_init();
    temp = epoint_init();
    tempC2 = epoint_init();
    BSGS = epoint_init();
    x1 = mirvar(0);
    x2 = mirvar(0);
    y1 = mirvar(0);
    y2 = mirvar(0);
    epoint_get(c1, x1, y1);
    epoint_get(c2, x2, y2);
    if (!epoint_x(x1) || !epoint_x(x2))
    {
        RuntimeLogger->error("Homo Decryption failed for point not on curve");
        throw PointNotOnCurve;
    }
    RuntimeLogger->info("Homo Decryption start");
    epoint_copy(c2, tempC2);
    ecurve_mult(sk, c1, temp);
    ecurve_sub(temp, c2);//now c2=mG
    epoint_copy(c2, mG);
    //printf("mG:\n");
    //epoint_print(mG);
    epoint_copy(tempC2, c2);
    for (int i = 0; i < MaxVoteNum; i++)
    {
        r = mirvar(i);
        ecurve_mult(r, G, BSGS);
        /*printf("BSGS:\n");
        epoint_print(BSGS);*/
        if (epoint_comp(BSGS, mG))
        {
            RuntimeLogger->info("Homo Decryption complete");
            *m = i;
            return;
        }
    }
    RuntimeLogger->error("Homo Decryption error for unknown reason");
    throw HomoDecryptionError;
}
big* GenPolyParam(int t)//生成一个多项式的随机参数
{
    big* aij = (big*)malloc(t * sizeof(big));//aij声明与初始化,
    for (int i = 0; i < t; i++)
    {
        aij[i] = mirvar(0);
    }
    for (int i = 0; i < t; i++)
    {
        bigbits(255, aij[i]);
    }
    return aij;//规定从左至右分别为a0,a1,a2,a3.....从常数项开始，一次项系数，二次项系数......
}
big Expoent(int n, big a)//计算a的n次方,注意这些a不可以是大数，只能是投票人数之类的小数
{
    big result = mirvar(1);
    for (int i = 0; i < n; i++)
    {
        multiply(result, a, result);
    }
    return result;
}
big GenYij(int t,int j,big *aij)//计算一个给定系数aij，和给定输入j的多项式的输出
{
    big fj = mirvar(0);
    big p = mirvar(1);
    big temp = mirvar(1);
    for (int a = 0; a < t; a++)
    {
        if (a == 0)
            add(aij[a], fj, fj);
        else
        {
            p = mirvar(j);
            temp = mirvar(1);
            multiply(aij[a], Expoent(a, p), temp);//aij*x^(j)
            add(temp, fj, fj);
        }
    }
    return fj;
}
big* CalFij(int n, int t, big* aij)//计算一个给定系数aij，的j个参数的数组
{
    big* ui = (big*)malloc(n * sizeof(big));
    big temp = mirvar(0);
    for (int i = 0; i < n; i++)
    {
        temp = GenYij(t, i+1, aij);
        ui[i] = temp;
    }
    return ui;
}
big* CalSecretShareGiven(int n, int t, big** aij)//计算给定了算出的yij二维数组，算出每一个Uj收到的Yij的和，也就是得出秘密份额Yj
{
    big q = mirvar(0);
    big temp = mirvar(0);
    bytes_to_big(32, Sm2CurveParamG_Order, q);
    big* result = (big*)malloc(n * sizeof(big));
    for (int i = 0; i < n; i++)
        result[i] = mirvar(0);
    for (int i = 0; i < n; i++)//对矩阵的每一列求和，采用行优先方法，防止人数过多时性能下降
    {
        for (int j = 0; j < n; j++)
        {
            add(result[j], aij[i][j], result[j]);
        }
    }
    for (int i = 0; i < n; i++)
    {
        divide(result[i], q, temp);

    }
    return result;
}
big CalNumerator(int r,int t)//给定一个r，给定一个t，计算delta函数的分子部分
{
    big acc = mirvar(1);
    big j = mirvar(0);
    for (int i = 1; i <= t ; i++)
    {
        j = mirvar(i);
        if (i == r)
            continue;
        negify(j, j);
        multiply(acc, j, acc);
    }
    return acc;
}
big CalDominator(int r, int t)//给定一个r，给定一个t，计算delta函数的分母部分
{
    big acc = mirvar(1);
    big temp = mirvar(0);
    big r_big = mirvar(r);
    big j = mirvar(0);
    for (int i = 1; i <= t; i++)
    {
        if (r == i)
            continue;
        j = mirvar(i);
        subtract(r_big, j, temp);//temp=r-j
        multiply(acc, temp, acc);
    }
    return acc;
}
big SecretShareSk(big *Yr,int t,big q)//用给定的SecretShare Yr计算秘密值sk
{
    big acc = mirvar(0);
    big NumAcc = mirvar(1);
    big Numerator = mirvar(0);//CalNumerator(r, t);
    big temp = mirvar(0);
    big Dominator = mirvar(0);//CalDominator(r, t);
    for (int i = 1; i <= t; i++)
    {
        Numerator = CalNumerator(i, t);
        Dominator = CalDominator(i, t);
        multiply(Numerator, Yr[i - 1], NumAcc);
        divide(NumAcc, Dominator, temp);
        divide(temp, q, q);//模q
        add(acc, temp, acc);
        temp = mirvar(0);
    }
    return acc;
}
epoint* SecretSharePk(big* Yr,big q, int t, epoint* G)//用给定的SecretShare Yr计算公钥，而不泄露私钥
{
    epoint* SharePk = epoint_init();
    epoint* PkAcc = epoint_init();
    big acc = mirvar(0);
    big NumAcc = mirvar(1);
    big Numerator = mirvar(0);//CalNumerator(r, t);
    big temp = mirvar(0);
    big Dominator = mirvar(0);//CalDominator(r, t);
    for (int i = 1; i <= t; i++)
    {
        Numerator = CalNumerator(i, t);
        Dominator = CalDominator(i, t);
        multiply(Numerator, Yr[i - 1], NumAcc);
        divide(NumAcc, Dominator, temp);
        divide(temp, q, q);//模q
        ecurve_mult(temp, G, SharePk);
        ecurve_add(SharePk, PkAcc);
        temp = mirvar(0);
    }
    return PkAcc;
}
big* GenPkbySecretShare(int n, int t, epoint*G,epoint *PkOut,big q)//输入总人数，参与秘密分享的人数，生成元G，输出一个公钥，以及随机数参数，用于解密时生成sk*C1
{
    big** RandomPolyParam = (big**)malloc((n * n) * sizeof(big));
    big** aij = (big**)malloc((n * n) * sizeof(big));
    big* SecretShare = (big*)malloc(n * sizeof(big));
    big sk = mirvar(0);
    epoint* pk = epoint_init();
    printf("秘密共享初始化完毕，正在生成公私钥：\n");
    /************************************************生成n个t-1次随机多项式**********************************************************/
    printf("正在生成随机多项式：\n\n");
    for (int i = 0; i < n; i++)
    {
        RandomPolyParam[i] = GenPolyParam(t);
    }
    
    printf("随机多项式生成成功：\n\n");
    /***************************************通过生成的n个t-1次多项式，计算对应的Ui***************************************************/
    printf("正在计算多项式值：\n\n");
    for (int i = 0; i < n; i++)
    {
        aij[i] = CalFij(n, t, RandomPolyParam[i]);
    }
    printf("计算成功：\n\n");
    /***************************************通过计算出的Ui，模拟通过星形拓扑发送至每一个参与者，计算Secret Share*********************/
    printf("正在计算秘密分享值：\n\n");
    SecretShare = CalSecretShareGiven(n, t, aij);
    printf("秘密分享值计算完毕：\n\n");
    /***************************************通过Secret Share，计算sk*G,即pk而不泄露sk************************************************/
    printf("生成PK中：\n\n");
    pk = SecretSharePk(SecretShare, q, t, G);
    printf("生成完毕：\n\n");
    epoint_copy(pk, PkOut);
    return SecretShare;
}
big GenSkBySecretShare(int t,big *SecretShare,big q)
{
    big sk = mirvar(0);
    sk = SecretShareSk(SecretShare, t, q);
    return sk;
}
