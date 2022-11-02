//#include "zpk.h"
//#include "voter.h"
//#include"SM2.h"
//#include"SM2RingSig.h"
//int main(int argc, char const* argv[])
//{
//	/*************************miracl系统建立********************************/
//
//	miracl* mip = mirsys(36, MAXBASE);
//	time_t seed;
//	time(&seed);
//	irand((unsigned long long)seed);
//	mip->IOBASE = HexIOBASAE;
//
//	/*************************参数声明*************************************/
//	big a, b, p, SkByShare, q, g_x, g_y, * SecretShare, Accumulator, SigKL;
//	int t, Mlength;
//	int* VoteResult;
//	int Number = 5;
//	char *VoteMessage;
//	int* VoteMessageInt;
//	point HomoC1, HomoC2, PK, G, * SigPk, AccC1, AccC2, C1, C2, HomoC1Acc, HomoC2Acc;
//	uint32_t* AccC3, * C3;
//	uint8_t* SigBL, ** Sigai, * Lhash, ** M;
//	voter* Voter;
//	big k, * SigSK;
//	a = mirvar(0);
//	b = mirvar(0);
//	p = mirvar(0);
//	q = mirvar(0);
//	g_x = mirvar(0);
//	g_y = mirvar(0);
//	/*************************miracl曲线运算系统建立********************************/
//	bytes_to_big(32, Sm2CurveParam_a, a);
//	bytes_to_big(32, Sm2CurveParam_b, b);
//	bytes_to_big(32, Sm2CurveParamPrime, p);
//	ecurve_init(a, b, p, MR_BEST);
//	/*****************************变量初始化********************************/
//	t = 3;
//	Mlength = 128;
//	M = (uint8_t**)malloc(Number * sizeof(uint8_t*));
//	for (int i = 0; i < Number; i++)
//		M[i] = (uint8_t*)malloc(128 * sizeof(uint8_t));
//	Lhash = (uint8_t*)malloc(32 * sizeof(uint8_t));
//	HomoC1Acc = epoint_init();
//	HomoC2Acc = epoint_init();
//	VoteResult = (int*)malloc(sizeof(int));
//	SigKL = mirvar(0);
//	SigBL = (uint8_t*)malloc(128 * sizeof(uint8_t));
//	Sigai = (uint8_t**)malloc(Number * sizeof(uint8_t*));
//	for (int i = 0; i < Number; i++)
//		Sigai[i] = (uint8_t*)malloc(32 * sizeof(uint8_t));
//	HomoC1 = epoint_init();
//	HomoC2 = epoint_init();
//	C1 = epoint_init();
//	C2 = epoint_init();
//	C3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
//	AccC1 = epoint_init();
//	AccC2 = epoint_init();
//	AccC3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
//	
//	SecretShare = (big*)malloc(Number * sizeof(big));
//	VoteMessage = (char*)malloc(Number * sizeof(char));
//	VoteMessageInt = (int*)malloc(Number * sizeof(int));
//	//测试用，随便赋值几个消息
//	VoteMessage[0] = 0;
//	VoteMessage[1] = 1;
//	VoteMessage[2] = 0;
//	VoteMessage[3] = 1;
//	VoteMessage[4] = 1;
//
//	VoteMessageInt[0] = 0;
//	VoteMessageInt[1] = 1;
//	VoteMessageInt[2] = 0;
//	VoteMessageInt[3] = 1;
//	VoteMessageInt[4] = 1;
//	SkByShare = mirvar(0);
//	HomoC1 = epoint_init();
//	HomoC2 = epoint_init();
//	PK = epoint_init();
//	G = epoint_init();
//	bytes_to_big(32, Sm2CurveParamG_x, g_x);
//	bytes_to_big(32, Sm2CurveParamG_y, g_y);
//	bytes_to_big(32, Sm2CurveParamG_Order, q);
//	epoint_set(g_x, g_y, 1, G);
//	SigPk = (point*)malloc(Number * sizeof(point));
//	SigSK = (big*)malloc(Number * sizeof(big));
//	for (int i = 0; i < Number; i++)
//		SigPk[i] = epoint_init();
//	Voter = (voter*)malloc(Number * sizeof(voter));
//	k = mirvar(0);
//	for (int i = 0; i < Number; i++)//签名公钥生成
//	{
//		SigSK[i] = mirvar(0);
//		bigbits(255, k);
//		copy(k, SigSK[i]);
//		ecurve_mult(k, G, SigPk[i]);
//	}
//	
//	/*****************************秘密共享生成公钥，秘密份额****************************/
//	SecretShare = GenPkbySecretShare(Number, t, G, PK, q);
//	SkByShare = GenSkBySecretShare(t, SecretShare, q);
//	Encryption(0, PK, G, AccC1, AccC2, AccC3);//初始聚合值是0的同态密文
//	/*epoint_print(PK);
//	for (int i = 0; i < N; i++)
//		cotnum(SecretShare[i], stdout);*/
//
//
//	/******************************Voter初始化******************************************/
//	for (int i = 0; i < Number; i++)
//	{
//		Voter[i].init(VoteMessage[i], PK, G, i);
//	}
//
//	/******************************投票内容加密******************************************/
//	for (int i = 0; i < Number; i++)
//	{
//		big C1X, C1Y, C2X, C2Y;
//		uint8_t* c1x, * c1y, * c2x, * c2y;
//		C1X = mirvar(0);
//		C1Y = mirvar(0);
//		C2X = mirvar(0);
//		C2Y = mirvar(0);
//		c1x = (uint8_t*)malloc(32 * sizeof(uint8_t));
//		c1y = (uint8_t*)malloc(32 * sizeof(uint8_t));
//		c2x = (uint8_t*)malloc(32 * sizeof(uint8_t));
//		c2y = (uint8_t*)malloc(32 * sizeof(uint8_t));
//		Encryption(VoteMessageInt[i], PK, G, C1, C2, C3);
//		epoint_get(C1, C1X, C1Y);
//		epoint_get(C2, C2X, C2Y);
//		big_to_bytes(32, C1X, (char*)c1x, RightJustify);
//		big_to_bytes(32, C1Y, (char*)c1y, RightJustify);
//		big_to_bytes(32, C2X, (char*)c2x, RightJustify);
//		big_to_bytes(32, C2Y, (char*)c2x, RightJustify);
//		for (int j = 0; j < 32; j++)
//			M[i][j] = c1x[i];
//		for (int j = 0; j < 32; j++)
//			M[i][j + 32] = c1y[i];
//		for (int j = 0; j < 32; j++)
//			M[i][j + 64] = c2x[i];
//		for (int j = 0; j < 32; j++)
//			M[i][j + 96] = c2y[i];
//		epoint_copy(C1, Voter[i].c1);
//		epoint_copy(C2, Voter[i].c2);
//		for (int j = 0; j < 8; j++)
//			Voter[i].c3[j] = C3[j];
//		/*epoint_print(AccC1);
//		epoint_print(AccC2);*/
//		try
//		{
//			HomoEncryption(C1, AccC1, C2, AccC2, HomoC1Acc, HomoC2Acc);
//			epoint_copy(HomoC1Acc, AccC1);
//			epoint_copy(HomoC2Acc, AccC2);
//			printf("\n");
//		}
//		catch (int error)
//		{
//			PrintErrorMessage(error);
//		}
//			
//	}
//	/******************************环签名******************************************/
//
//	big KL = mirvar(0);
//	KL = SM2RingSigGen(G, SigPk, SigSK[2], SigBL, Sigai, M[2], Number, 2, Mlength, Lhash);
//	SM2RingSigProof(G, SigPk, SigBL, Sigai, M[2], Number, 2, Mlength, KL);
//	
//	/******************************开票******************************************/
//	
//	HomoDecryption(AccC1, AccC2, G, SkByShare, VoteResult);
//	printf("\n%d ", *VoteResult);
//}