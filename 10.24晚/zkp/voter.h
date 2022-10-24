#pragma once
#include"SM2.h"
#include"SM2RingSig.h"
#include"SM2_Param.h"
#include"SM2_STANDARD.h"
#include"sm3.h"
#include"SM3acl.h"
#include"SM3def.h"
#include"zpk.h"
#include<iostream>

using namespace std;


class voter
{
 
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
    int n = 200;
    int t = 50;
    epoint* SPK;

    //------------------------zkp var----------------------//

    int vote_m;
public:
    epoint* A1, * A2, * mG;
    big challenge, m_big, response;
    int PorV;

public:
    void init(char m) {
        //----------------------sm2_Enc init----------------------//
        vote_m = (int)m;
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
        bytes_to_big(32, Sm2CurveParamG_Order, q);
        G = epoint_init();
        pk = epoint_init();
        c1 = epoint_init();
        c2 = epoint_init();
        Agg_C1 = epoint_init();
        Agg_C2 = epoint_init();
        c3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
        c1_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
        c1_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
        c2_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
        c2_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
        ecurve_init(a, b, p, MR_BEST);
        epoint_set(g_x, g_y, cb, G);
        ecurve_mult(sk, G, pk);
        epoint* SPK = epoint_init();
        big* SecretShare = GenPkbySecretShare(n, t, G, SPK, q);
        SkByShare = GenSkBySecretShare(t, SecretShare, q);
        epoint* VerfPk = epoint_init();
        ecurve_mult(SkByShare, G, VerfPk);

        //-----------------------zkp init------------------------//
        challenge = mirvar(0);
        m_big = mirvar(0);
        response = mirvar(0);
        G = epoint_init();
        mG = epoint_init();
        A1 = epoint_init();
        A2 = epoint_init();
        convert(vote_m, m_big);
        ecurve_mult(m_big, G, mG);
    }
	
	/****************************** 1.生成密钥 **************************/
    void KeyGen(){

    }
	
	/******************************* 2.VRF ******************************/
    
	/***************************** 3.Encrypt ****************************/
    void Enc() {
        Encryption(vote_m, SPK, G, c1, c2, c3);
        //big kk = mirvar(0);
        //bytes_to_big(32, k1, kk);
        //？？？可以去掉这两句吗？？？
        //？？？还没有转化成字符串并存储
    }
    void Dec(epoint* Agg_C1, epoint*Agg_C2){
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
    void zkp(int PorV) {
        if (PorV == 0) {
            //0代表是Prover
            Prover P;
            P.init();
            P.ProverGenA1A2(G);
            A1 = P.A1;
            P.ProverGenResponse(challenge, G);
            response = P.response;
        }
        if (PorV == 1) {
            //V代表是Verifier
            Verifier V;
            V.init();
            V.VerifierGenChallenge();
            challenge = V.challenge;
            V.VerifierVerify(response, G, mG, A1, A2);
        } 
    }
	/**************************** 5.RingSign ***************************/


};

