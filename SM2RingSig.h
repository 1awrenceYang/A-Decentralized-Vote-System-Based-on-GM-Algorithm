#ifndef SM2_RING_SIG_H
#define SM2_RING_SIG_H
#include"SM2_STANDARD.h"
typedef epoint* point;
typedef unsigned int uint;
void GetSeq(int m, int L, int* Out)
{
	int counter = 0;
	int* index = (int*)malloc((m - 1) * sizeof(int));
	for (int j = L + 1; j <= m; j++)
	{
		index[counter] = j - 1;
		counter = counter + 1;
	}
	for (int j = 1; j <= L - 1; j++)
	{
		index[m - L + j - 1] = j - 1;
	}//index存储着 L+1 ---M---L-1的顺序
	for (int i = 0; i < m - 1; i++)
		Out[i] = index[i];

	free(index);
}
void Convert(uint32_t* Input, uint8_t* Output)
{
	//PrintSM3(Input);
	uint8_t* Ptr = (uint8_t*)Input;
	for (int i = 0; i < 32; i=i+4)
	{
		Output[i + 3] = Ptr[i + 0];
		Output[i + 2] = Ptr[i + 1];
		Output[i + 1] = Ptr[i + 2];
		Output[i + 0] = Ptr[i + 3];
		//printf("%02X%02X%02X%02X ", Output[i + 3], Output[i + 2], Output[i + 1], Output[i + 0]);
	}
}
void GetHashByPKandM(point* PKs, uint8_t* M, uint8_t *Output, uint m, uint Mlength)
{//PKs:公钥集合  M：明文消息   m：集合阶 Mlength：明文字节长度
	uint HashinputBitLenth = 0;
	uint HashinputByteLength = 0;
	HashinputBitLenth = (m * 64 + Mlength) * 8;//哈希输入的比特长度
	HashinputByteLength = HashinputBitLenth / 8;//哈希输入的字节长度
	uint8_t* Hashinput = (uint8_t*)malloc(HashinputByteLength * sizeof(uint8_t));
	uint8_t* ux, * uy;//公钥两个坐标
	uint8_t* HashOutputU8 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	uint32_t* HashOutputU32 = (uint32_t*)malloc(8 * sizeof(uint32_t));
	big X, Y;
	ux = (uint8_t*)malloc(32 * sizeof(uint8_t));
	uy = (uint8_t*)malloc(32 * sizeof(uint8_t));
	X = mirvar(0);
	Y = mirvar(0);
	for (int i = 0; i < Mlength; i++)//级联M
		Hashinput[i] = M[i];
	for (int i = 0; i < m; i++)
	{
		epoint_get(PKs[i], X, Y);
		big_to_bytes(32, X, (char*)ux, RightJustify);
		big_to_bytes(32, Y, (char*)uy, RightJustify);
		//Align8Print(ux, 32);
		//Align8Print(uy, 32);
		for (int j = 0; j < 32; j++)//M||Pix
		{
			Hashinput[Mlength + 64 * i + j] = ux[j];
			//rintf("%02X", Hashinput[Mlength + 64 * i + j]);
		}
		for (int j = 0; j < 32; j++)
		{
			Hashinput[Mlength + 64 * i + 32 + j] = uy[j];//M||Pix||Piy
			//printf("%02X", Hashinput[Mlength + 64 * i + 32 + j]);
		}
	}
	//Align8Print(Hashinput, HashinputByteLength);
	SM3(Hashinput, HashOutputU32, HashinputBitLenth);
	Convert(HashOutputU32, HashOutputU8);
	
	//PrintSM3(HashOutputU32);
	//Align8Print(HashOutputU8, 32);
	for (int i = 0; i < 32; i++)
		Output[i] = HashOutputU8[i];
	free(Hashinput);
	free(ux);
	free(uy);
	free(HashOutputU8);
	free(HashOutputU32);
	mirkill(X);
	mirkill(Y);
}
void CalculateBL1_BL2(point G, uint8_t* BL1, uint8_t* BL2,big OutK)
{
	big KL, BL1_x, BL1_y, BL2_random;
	KL = mirvar(0);
	BL1_x = mirvar(0);
	BL1_y = mirvar(0);
	BL2_random = mirvar(0);
	uint8_t* bl1_x, * bl1_y, *bl2;
	bl1_x = (uint8_t*)malloc(32 * sizeof(uint8_t));
	bl1_y = (uint8_t*)malloc(32 * sizeof(uint8_t));
	bl2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	bigbits(255, KL);
	bigbits(256, BL2_random);
	big_to_bytes(32, BL2_random, (char*)bl2, RightJustify);
	point BL1_point;
	BL1_point = epoint_init();
	ecurve_mult(KL, G, BL1_point);
	epoint_get(BL1_point, BL1_x, BL1_y);
	big_to_bytes(32, BL1_x, (char*)bl1_x, RightJustify);
	big_to_bytes(32, BL1_y, (char*)bl1_y, RightJustify);
	for (int i = 0; i < 32; i++)
		BL2[i] = bl2[i];
	for (int i = 0; i < 32; i++)
		BL1[i] = bl1_x[i];
	for (int i = 0; i < 32; i++)
		BL1[32 + i] = bl1_y[i];
	copy(KL, OutK);
	mirkill(KL);
	mirkill(BL1_x);
	mirkill(BL1_y);
	mirkill(BL2_random);
	free(bl1_x);
	free(bl1_y);
	free(bl2);
	epoint_free(BL1_point);
	
}
void CalculateBi( point G, point PK, uint8_t *Bl_12, uint8_t *ai, uint8_t *Lhash, uint8_t *BL)//输入：PK是该成员的公钥,这个函数计算单个成员的密文
{//Bl_12即是b(L-1)2,用于计算bi2用
	big k, Xi2, Yi2, X, Y;
	uint8_t* xi2, * yi2, * x, * y, * Xi2andYi2, * ti, * HashoutputChar, * bi2, * bi1, * bi3, * bi3Hashinput;
	uint32_t* HashoutputU32, * bi3U32;
	point KiPi, Bi1;
	k = mirvar(0);
	Xi2 = mirvar(0);
	Yi2 = mirvar(0);
	X = mirvar(0);
	Y = mirvar(0);
	bi1 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	bi2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	bi3 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	bi3Hashinput = (uint8_t*)malloc(128 * sizeof(uint8_t));
	xi2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	yi2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	x = (uint8_t*)malloc(32 * sizeof(uint8_t));
	y = (uint8_t*)malloc(32 * sizeof(uint8_t));
	HashoutputChar = (uint8_t*)malloc(32 * sizeof(uint8_t));
	HashoutputU32 = (uint32_t*)malloc(8 * sizeof(uint32_t));
	bi3U32 = (uint32_t*)malloc(8 * sizeof(uint32_t));
	Xi2andYi2 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	ti = (uint8_t*)malloc(32 * sizeof(uint8_t));
	KiPi = epoint_init();
	Bi1 = epoint_init();
	bigbits(255, k);
	ecurve_mult(k, G, Bi1);
	epoint_get(Bi1, X, Y);
	big_to_bytes(32, X, (char*)x, RightJustify);
	big_to_bytes(32, Y, (char*)y, RightJustify);
	for (int i = 0; i < 32; i++)
		bi1[i] = x[i];
	for (int i = 0; i < 32; i++)
		bi1[32 + i] = y[i];//得到bi1
	ecurve_mult(k, PK, KiPi);
	epoint_get(KiPi, Xi2, Yi2);
	big_to_bytes(32, Xi2, (char*)xi2, RightJustify);
	big_to_bytes(32, Yi2, (char*)yi2, RightJustify);
	for (int i = 0; i < 32; i++)
		Xi2andYi2[i] = xi2[i];
	for (int i = 0; i < 32; i++)
		Xi2andYi2[32 + i] = yi2[i];
	KDF(Xi2andYi2, ti, 64);
	SM3(Bl_12, HashoutputU32, 256);
	Convert(HashoutputU32, HashoutputChar);//得到H(b(i-1)2)
	for (int i = 0; i < 32; i++)//得到bi2
		bi2[i] = ai[i] ^ Lhash[i] ^ HashoutputChar[i] ^ ti[i];

	for (int i = 0; i < 32; i++)
		bi3Hashinput[i] = xi2[i];
	for (int i = 0; i < 32; i++)
		bi3Hashinput[32 + i] = Lhash[i];
	for (int i = 0; i < 32; i++)
		bi3Hashinput[64 + i] = bi2[i];
	for (int i = 0; i < 32; i++)
		bi3Hashinput[96 + i] = yi2[i];

	SM3(bi3Hashinput, bi3U32, 128 * 8);
	Convert(bi3U32, bi3);


	for (int i = 0; i < 64; i++)
		BL[i] = bi1[i];
	for (int i = 0; i < 32; i++)
		BL[64 + i] = bi2[i];
	for (int i = 0; i < 32; i++)
		BL[96 + i] = bi3[i];

	free(xi2);
	free(yi2);
	free(x);
	free(y);
	free(Xi2andYi2);
	free(ti);
	free(HashoutputChar);
	free(bi2);
	free(bi1);
	free(bi3);
	free(bi3Hashinput);
	free(HashoutputU32);
	free(bi3U32);
	mirkill(k);
	mirkill(Xi2);
	mirkill(Yi2);
	mirkill(X);
	mirkill(Y);
	epoint_free(KiPi);
	epoint_free(Bi1);
}
void Genai(int* Seq, int m, uint8_t** ai)//ai输入时用全0字节初始化值
{
	big rand;
	rand = mirvar(0);
	int Row = 0;
	uint8_t** aL = (uint8_t**)malloc(m * sizeof(uint8_t*));
	uint8_t* tempai = (uint8_t*)malloc(32 * sizeof(uint8_t));
	for (int i = 0; i < m; i++)
		aL[i] = (uint8_t*)malloc(32 * sizeof(uint8_t));
	for (int i = 0; i < m - 1; i++)
	{
		bigbits(256, rand);
		Row = Seq[i];
		big_to_bytes(32, rand, (char*)tempai, RightJustify);
		for (int j = 0; j < 32; j++)
		{
			aL[Row][j] = tempai[j];
		}
		//Align8Print(aL[Row], 32);
	}
	for (int i = 0; i < m - 1; i++)
	{
		Row = Seq[i];
		for (int j = 0; j < 32; j++)
			ai[Row][j] = aL[Row][j];
	}
	mirkill(rand);
	free(tempai);
	for (int i = 0; i < m; i++)
		free(aL[i]);
	free(aL);
}
void CalculateAL(uint8_t* BL, uint8_t* LHash, big SK, uint8_t* Bl_12, uint m, uint L, uint8_t** ai)
{//BL输入时，只有BL1 BL2计算出来了，结束时，会计算出BL3，ai会计算出aL，aL在输入时是全0字节
	uint8_t* BL1x, * BL1y, * xL2, * yL2, * XL2andYL2, * tL, * ForALHashoutputChar, * BL2, * AL, * BL3, * ForBL3Hashinput;
	uint32_t* ForALHashOutput, * ForBL3Hashoutput;
	big BL1X, BL1Y, XL2, YL2;
	point SK_BL1, BL1;
	ForBL3Hashoutput = (uint32_t*)malloc(8 * sizeof(uint32_t));
	ForALHashOutput = (uint32_t*)malloc(8 * sizeof(uint32_t));
	ForALHashoutputChar = (uint8_t*)malloc(32 * sizeof(uint8_t));
	ForBL3Hashinput = (uint8_t*)malloc(128 * sizeof(uint8_t));
	AL = (uint8_t*)malloc(32 * sizeof(uint8_t));
	BL3 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	BL1x = (uint8_t*)malloc(32 * sizeof(uint8_t));
	BL1y = (uint8_t*)malloc(32 * sizeof(uint8_t));
	xL2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	yL2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	tL = (uint8_t*)malloc(32 * sizeof(uint8_t));
	BL2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	XL2andYL2 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	BL1X = mirvar(0);
	BL1Y = mirvar(0);
	XL2 = mirvar(0);
	YL2 = mirvar(0);
	SK_BL1 = epoint_init();
	BL1 = epoint_init();
	for (int i = 0; i < 32; i++)
		BL1x[i] = BL[i];
	for (int i = 0; i < 32; i++)
		BL1y[i] = BL[32 + i];
	bytes_to_big(32, (char*)BL1x, BL1X);
	bytes_to_big(32, (char*)BL1y, BL1Y);
	epoint_set(BL1X, BL1Y, 1, BL1);
	ecurve_mult(SK, BL1, SK_BL1);
	epoint_get(SK_BL1, XL2, YL2);
	big_to_bytes(32, XL2, (char*)xL2, RightJustify);
	big_to_bytes(32, YL2, (char*)yL2, RightJustify);
	for (int i = 0; i < 32; i++)
		XL2andYL2[i] = xL2[i];
	for (int i = 0; i < 32; i++)
		XL2andYL2[32 + i] = yL2[i];
	KDF(XL2andYL2, tL, 64);
	SM3(Bl_12, ForALHashOutput, 256);
	Convert(ForALHashOutput, ForALHashoutputChar);
	for (int i = 0; i < 32; i++)
		BL2[i] = BL[64 + i];
	for (int i = 0; i < 32; i++)
		AL[i] = BL2[i] ^ tL[i] ^ LHash[i] ^ ForALHashoutputChar[i];//计算aL

	for (int i = 0; i < 32; i++)
		ForBL3Hashinput[i] = xL2[i];
	for (int i = 0; i < 32; i++)
		ForBL3Hashinput[32 + i] = LHash[i];
	for (int i = 0; i < 32; i++)
		ForBL3Hashinput[64 + i] = BL2[i];
	for (int i = 0; i < 32; i++)
		ForBL3Hashinput[96 + i] = yL2[i];

	SM3(ForBL3Hashinput, ForBL3Hashoutput, 128 * 8);
	Convert(ForBL3Hashoutput, BL3);
	for (int i = 0; i < 32; i++)//回传aL
		ai[L - 1][i] = AL[i];
	for (int i = 0; i < 32; i++)//回传BL3
		BL[96 + i] = BL3[i];

	free(BL1x);
	free(BL1y);
	free(xL2);
	free(yL2);
	free(XL2andYL2);
	free(tL);
	free(ForALHashoutputChar);
	free(BL2);
	free(AL);
	free(BL3);
	free(ForBL3Hashinput);
	free(ForALHashOutput);
	free(ForBL3Hashoutput);
	mirkill(BL1X);
	mirkill(BL1Y);
	mirkill(XL2);
	mirkill(YL2);
	epoint_free(SK_BL1);
	epoint_free(BL1);
}
big SM2RingSigGen(point G, point* PKs, big SKL, uint8_t* bL, uint8_t** aL, uint8_t* M, uint m, uint L, uint Mlength, uint8_t* Lhash_reulst)
{
	/************************************************其他参数声明***********************************************************/
	int* Seq, Row;
	/************************************************其他参数声明***********************************************************/



	/************************************************uint8_t 变量声明***********************************************************/
	uint8_t* Lhash, ** tempaL, ** tempbL, * BL1, * BL2, * Bl_12, * Bl_12forAL;
	/************************************************uint8_t 变量声明***********************************************************/


	/************************************************bigtype 变量声明***********************************************************/
	big KL;
	/************************************************bigtype 变量声明***********************************************************/





	/************************************************uint8_t 变量内存分配***********************************************************/
	Lhash = (uint8_t*)malloc(32 * sizeof(uint8_t));
	BL1 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	BL2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	Seq = (int*)malloc((m - 1) * sizeof(int));
	tempaL = (uint8_t**)malloc(m * sizeof(uint8_t*));
	Bl_12 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	Bl_12forAL = (uint8_t*)malloc(32 * sizeof(uint8_t));
	for (int i = 0; i < m; i++)
		tempaL[i] = (uint8_t*)malloc(32 * sizeof(uint8_t));
	tempbL = (uint8_t**)malloc(m * sizeof(uint8_t*));
	for (int i = 0; i < m; i++)
		tempbL[i] = (uint8_t*)malloc(128 * sizeof(uint8_t));
	/************************************************uint8_t 变量内存分配***********************************************************/



	/************************************************bigtype 变量内存分配***********************************************************/
	KL = mirvar(0);
	/************************************************bigtype 变量内存分配***********************************************************/


	
	




	/***********************************************初始化过程***********************************************************/
	GetSeq(m, L, Seq);//取得迭代顺序 L+1 --- M ---- L-1
	GetHashByPKandM(PKs, M, Lhash, m, Mlength);//取得L=H（M||P1||P2||P3......Pi）

	for (int i = 0; i < m; i++)//用0初始化aL
	{
		for (int j = 0; j < 32; j++)
			tempaL[i][j] = 0;
	}

	for (int i = 0; i < m; i++)//用0初始化bL
	{
		for (int j = 0; j < 128; j++)
			tempbL[i][j] = 0;
	}
	/***********************************************初始化过程***********************************************************/


	/***********************************************随机生成aL***********************************************************/
	Genai(Seq, m, tempaL);
	/***********************************************随机生成aL***********************************************************/



	/***********************************************计算BL1 BL2***********************************************************/
	CalculateBL1_BL2(G, BL1, BL2, KL);
	for (int i = 0; i < 64; i++)
		tempbL[L - 1][i] = BL1[i];
	for (int i = 0; i < 32; i++)
		tempbL[L - 1][64 + i] = BL2[i];
	/***********************************************计算BL1 BL2***********************************************************/



	/***********************************************计算B(L+1)-B(m)-B(L-1)***********************************************************/
	for (int i = 0; i < m - 1; i++)
	{
		Row = Seq[i];
		if (Row == 0)//如果Row=0，b(i-1)2 应该是b(m)2
		{
			for (int j = 0; j < 32; j++)
				Bl_12[j] = tempbL[m - 1][j];
		}
		else
		{
			for (int j = 0; j < 32; j++)
				Bl_12[j] = tempbL[Row - 1][j];
		}
		CalculateBi(G, PKs[Row], Bl_12, tempaL[Row], Lhash, tempbL[Row]);
	}
	/***********************************************计算B(L+1)-B(m)-B(L-1)***********************************************************/



	/***********************************************计算AL***********************************************************/
	if (L - 1 == 0)
	{
		for (int i = 0; i < 32; i++)
			Bl_12forAL[i] = tempbL[m - 1][i];
	}
	else
	{
		for (int i = 0; i < 32; i++)
			Bl_12forAL[i] = tempbL[L - 2][i];
	}
	CalculateAL(tempbL[L - 1], Lhash, SKL, Bl_12forAL, m, L, tempaL);
	/***********************************************计算AL***********************************************************/



	/***********************************************回传结果***********************************************************/
	for (int i = 0; i < m; i++)
	{
		for (int j = 0; j < 32; j++)
			aL[i][j] = tempaL[i][j];
	}

	for (int i = 0; i < 128; i++)
		bL[i] = tempbL[L - 1][i];

	for (int i = 0; i < 32; i++)
		Lhash_reulst[i] = Lhash[i];
	/***********************************************回传结果***********************************************************/




	/***********************************************释放内存***********************************************************/
	free(Seq);
	for (int i = 0; i < m; i++)
		free(tempbL[i]);
	free(tempbL);
	for (int i = 0; i < m; i++)
		free(tempaL[i]);
	free(tempaL);
	free(BL1);
	free(BL2);
	free(Bl_12);
	free(Bl_12forAL);
	return KL;
}
#endif 

