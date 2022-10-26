#pragma once
#include"SM2.h"
#include"SM2RingSig.h"
#include"SM2_Param.h"
#include"SM2_STANDARD.h"
#include"SM3acl.h"
#include"SM3acl.h"
#include"SM3def.h"
#include"zpk.h"
#include<iostream>

using namespace std;


class voter
{
    string name;//随机生成一串字符作为id和vrf的输入
    uint8_t* M;
    //------------------------sm2_Enc var-------------------------//
    int plaintext = 1;
    int cb = 0;
    big sk, k, a, b, p, g_x, g_y, c1_x_big, c1_y_big, c2_x_big, c2_y_big, q, SkByShare;
public:
    epoint* Agg_C1, * Agg_C2; //同态聚合所有加密选票后的结果
    epoint* pk, * G, * c1, * c2;
    uint32_t* c3;
    uint8_t* c1_x, * c1_y, * c2_x, * c2_y;
    char* k1 = (char*)malloc(32 * sizeof(char));
    int m = 5;
    int t = 3;
    epoint* SPK;

    //------------------------zkp var----------------------//

    int vote_m;
public:
    epoint* A1, * A2, * mG;
    big challenge, m_big, response;
    int PorV;
    //------------------------sig var--------------------//
    const int Mlength = 128;
    uint L = 0;//序号
    big sk_sig;
public:
    void init(char m, point PkbySecretShare, point InputG, int numb)
    {
        this->M = (uint8_t*)malloc(128 * sizeof(uint8_t));
        //----------------------sm2_Enc init----------------------//
        this->vote_m = (int)m;
        this->sk = mirvar(2);
        //cout << "sk******";
        //cotnum(this->sk, stdout);
        this->q = mirvar(0);
        this->SkByShare = mirvar(0);
        this->k = mirvar(0);
        this->c1_x_big = mirvar(0);
        this->c1_y_big = mirvar(0);
        this->c2_x_big = mirvar(0);
        this->c2_y_big = mirvar(0);
        bigbits(256, sk);
        this->g_x = mirvar(0);
        this->g_y = mirvar(0);
        this->c1 = epoint_init();
        this->c2 = epoint_init();
        this->pk = epoint_init();
        this->SPK = epoint_init();
        this->Agg_C1 = epoint_init();
        this->Agg_C2 = epoint_init();
        this->G = epoint_init();
        this->c3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
        this->c1_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
        this->c1_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
        this->c2_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
        this->c2_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
        /* bytes_to_big(32, Sm2CurveParamG_x, this->g_x);
         bytes_to_big(32, Sm2CurveParamG_y, this->g_y);
         epoint_set(g_x, g_y, cb, this->G);*/
         //epoint_print(this->G);
         //ecurve_mult(sk, G, pk);
        epoint_copy(InputG, this->G);
        epoint_copy(PkbySecretShare, this->SPK);
        //-----------------------zkp init------------------------//
        this->challenge = mirvar(0);
        this->m_big = mirvar(0);
        this->response = mirvar(0);
        //this->G = epoint_init();
        this->mG = epoint_init();
        this->A1 = epoint_init();
        this->A2 = epoint_init();
        convert(vote_m, m_big);
        ecurve_mult(m_big, G, mG);
        //--------------------------sig init--------------------//
        this->L = (uint)numb;
        this->PorV = numb;
        this->sk_sig = mirvar(0);
    }



    /******************************* 2.VRF ******************************/

    /***************************** 3.Encrypt ****************************/
    void Enc()
    {
        Encryption(this->vote_m, this->SPK, this->G, this->c1, this->c2, this->c3);
        //big kk = mirvar(0);
        //bytes_to_big(32, k1, kk);
        //？？？可以去掉这两句吗？？？
        //？？？还没有转化成字符串并存储
    }
    void Dec(epoint* Agg_C1, epoint* Agg_C2) {
        try
        {
            int m2 = 0;
            HomoDecryption(Agg_C1, Agg_C2, G, SkByShare, &m2);
            printf("HomoDecryption result:\n");
            printf("%x", m2);
        }
        catch (int error)
        {
            PrintErrorMessage(error);
        }
    }

    /********************************** 4.zkp *********************************/
    //void zkp(int PorV) {
    //    if (PorV == 0) {
    //        //0代表是Prover
    //        Prover P;
    //        P.init(m);
    //        P.ProverGenA1A2(G);
    //        A1 = P.A1;
    //        P.ProverGenResponse(m, challenge, G);
    //        response = P.response;
    //        cout << "prover done\n";
    //    }
    //    if (PorV == 1) {
    //        //V代表是Verifier
    //        Verifier V;
    //        V.init();
    //        V.VerifierGenChallenge();
    //        challenge = V.challenge;
    //        V.VerifierVerify(response, G, mG, A1, A2);
    //        cout << "verifier done\n";
    //    }
    //}
    /**************************** 5.RingSign ***************************/
    void getsignature_init(point* PK_sig)
    {
        big c1x, c2x, c1y, c2y;
        c1x = mirvar(0);
        c2x = mirvar(0);
        c1y = mirvar(0);
        c2y = mirvar(0);
        epoint_get(c1, c1x, c1y);
        epoint_get(c2, c2x, c2y);
        big_to_bytes(32, c1x, (char*)c1_x, RightJustify);
        big_to_bytes(32, c2x, (char*)c2_x, RightJustify);
        big_to_bytes(32, c1y, (char*)c1_y, RightJustify);
        big_to_bytes(32, c2y, (char*)c2_y, RightJustify);
        this->c1_x = (uint8_t*)c1_x;
        this->c1_y = (uint8_t*)c1_y;
        this->c2_x = (uint8_t*)c2_x;
        this->c2_y = (uint8_t*)c2_y;
        for (int i = 0; i < 32; i++) {
            this->M[i] = c1_x[i];
            this->M[i + 32] = c1_y[i];
            this->M[i + 64] = c2_x[i];
            this->M[i + 96] = c2_y[i];
        }
        PK_sig[L] = epoint_init();
        bigbits(255, k);
        ecurve_mult(k, G, PK_sig[L]);
        //this->sk_sig = k;
        copy(k, this->sk_sig);
    }
    void get_signature(point* PK_sig, uint8_t* BL, uint8_t** ai, big KL) {
        uint8_t* Lhash = (uint8_t*)malloc(32 * sizeof(uint8_t));
        uint8_t* BL1BL2 = (uint8_t*)malloc(96 * sizeof(uint8_t));
        //uint8_t* BL = (uint8_t*)malloc(128 * sizeof(uint8_t));
        uint8_t* Bl_12 = (uint8_t*)malloc(32 * sizeof(uint8_t));
        /* uint8_t** ai = (uint8_t**)malloc(m * sizeof(uint8_t*));
         for (int i = 0; i < m; i++)
             ai[i] = (uint8_t*)malloc(32 * sizeof(uint8_t));
         for (int i = 0; i < m; i++)
         {
             for (int j = 0; j < 32; j++)
                 ai[i][j] = 0;
         }*/
         //big KL = mirvar(0);
        KL = SM2RingSigGen(this->G, PK_sig, this->sk_sig, BL, ai, this->M, this->m, this->L, this->Mlength, Lhash);
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
    }
    void ver_signature(uint8_t* BL, uint8_t** ai, big KL, point* PK_sig) {
        SM2RingSigProof(G, PK_sig, BL, ai, M, m, L, Mlength, KL);
    }

};