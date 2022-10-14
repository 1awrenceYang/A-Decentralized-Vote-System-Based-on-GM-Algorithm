#ifndef SM2_STANDARD_H
#define SM2_STANDARD_H
extern "C"
{
#include"miracl.h"
#include"mirdef.h"
}
#include"SM2.h"
#include"SM2_Param.h"
#include<stdio.h>
#include<cstdlib>
#include <cstdint>
#include"SM3acl.h"
void LittleEnd2BigEnd(uint32_t input,uint8_t *output)
{
	uint8_t t1, t2, t3, t4;
	t1 = input & 0x000000ff;
	t2 = (input >> 8) & 0x000000ff;
	t3 = (input >> 16) & 0x000000ff;
	t4 = (input >> 24) & 0x000000ff;
	output[0] = t1;
	output[1] = t2;
	output[2] = t3;
	output[3]=t4;
}
void ConnectLength(uint8_t* Input, uint8_t* Output, unsigned int Length, unsigned int ConnectValue)//Length是字节长度，ConnectValue是整数
{
	uint8_t* temp = (uint8_t*)malloc((Length + 4) * sizeof(uint8_t));
	for (int i = 0; i < Length; i++)
		temp[i] = Input[i];
	uint8_t* ptr = (uint8_t*)&ConnectValue;

	int re = 0;
	bool bin[32] = { 0 };
	int value = 0;
	int c = 0;
	while (ConnectValue != 0)
	{
		re = ConnectValue % 2;
		bin[31 - c] = re;
		c++;
		ConnectValue = ConnectValue / 2;
	}//得到ConnectValue的二进制表示
	for (int i = 0; i < 32; i = i + 8)
	{
		value= 128 * bin[i] + 64 * bin[i + 1] + 32 * bin[i + 2] + 16 * bin[i + 3] + 8 * bin[i + 4] + 4 * bin[i + 5] + 2 * bin[i + 6] + bin[i + 7];
		temp[Length + i / 8] = value;
	}
	for (int i = 0; i < Length + 4; i++)
		Output[i] = temp[i];
	free(temp);
}
void KDF(uint8_t* Z, uint8_t* K, int lenZ, unsigned int klen = 256)
{
	int OutKeyLen = klen / 8;
	int n = 0;
	if (klen % 256 == 0)
		n = klen / 256;
	else
		n = (klen / 256) + 1;
	uint32_t* Ks = (uint32_t*)malloc(8 * n * sizeof(uint32_t));//分配空间
	memset(Ks, 0, 8 * n * sizeof(uint32_t));
	uint32_t* KsPtr = Ks;
	uint8_t* temp = (uint8_t*)malloc((lenZ + 4) * sizeof(uint8_t));
	for (int i = 1; i <= n; i++)
	{
		ConnectLength(Z, temp, lenZ, i);
		SM3(temp, Ks, (lenZ + 4) * 8);
		Ks = Ks + 8;
	}
	uint8_t* ptr = (uint8_t*)KsPtr;
	int Remain = OutKeyLen % 4;
	int ByteNum = OutKeyLen - Remain;
	for (int i = 0; i < ByteNum; i = i + 4)//按照大端顺序取出密钥
	{
		int a = i + 4;
		K[i] = ptr[a - 1];
		K[i + 1] = ptr[a - 2];
		K[i + 2] = ptr[a - 3];
		K[i + 3] = ptr[a - 4];
		//printf("%02X%02X%02X%02X ", K[i], K[i + 1], K[i + 2], K[i + 3]);
	}
	for (int i = 0; i < Remain; i++)
	{
		K[ByteNum + i] = ptr[ByteNum + (3 - i)];
		//printf("%02X", K[ByteNum + i]);
	}
	
	
}
void Point2BitString(epoint* point, uint8_t* Output)
{
	uint8_t* X, * Y, * temp;
	big x, y;
	x = mirvar(0);
	y = mirvar(0);
	X = (uint8_t*)malloc(32 * sizeof(uint8_t));
	Y = (uint8_t*)malloc(32 * sizeof(uint8_t));
	temp = (uint8_t*)malloc((32 + 32 + 1) * sizeof(uint8_t));
	epoint_get(point, x, y);
	big_to_bytes(32, x, (char*)X, RightJustify);
	big_to_bytes(32, y, (char*)Y, RightJustify);
	temp[0] = 0x04;
	for (int i = 0; i < 32; i++)
		temp[i + 1] = X[i];
	for (int i = 0; i < 32; i++)
		temp[33 + i] = Y[i];
	for (int i = 0; i < 65; i++)
		Output[i] = temp[i];
	free(X);
	free(Y);
	free(temp);
}
void SM2Encryption(epoint* G, epoint * Pk , uint8_t* M, unsigned int Length,uint8_t *Ciphertext)//输入明文串M，明文bit长度Length
{
	big k, h, X2, Y2;
	epoint* C1, * hPK, * kPK;
	uint8_t* C1BitString, * X2cordinateInput, * Y2cordinateInput, * X2cordinateOutput, * Y2cordinateOutput,
		* x2, * y2, * X2andY2, * C2, * ptr, * t, * HashInput, * C, * u8C3;
	uint32_t * C3;
	int n;
	n = 0;
	if (Length % 256 == 0)
		n = Length / 256;
	else
		n = (Length / 256) + 1;
	C1BitString = (uint8_t*)malloc(65 * sizeof(uint8_t));
	t = (uint8_t*)malloc((Length / 8) * sizeof(uint8_t));
	C3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
	x2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	y2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	X2andY2 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	C2 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	HashInput = (uint8_t*)malloc(((512 + Length) / 8) * sizeof(uint8_t));
	C = (uint8_t*)malloc((65 + 32 + Length / 8) * sizeof(uint8_t));
	u8C3 = (uint8_t*)malloc(32 * sizeof(uint8_t));
	C1 = epoint_init();
	hPK = epoint_init();
	kPK = epoint_init();
	k = mirvar(0);
	h = mirvar(1);
	X2 = mirvar(0);
	Y2 = mirvar(0);
	//----------------------------------------------A1阶段-----------------------------------------------------------check
	//bigbits(256, k);
	bytes_to_big(32, TempK, k);
	//cotnum(k, stdout);
	//----------------------------------------------A1阶段-----------------------------------------------------------


	//----------------------------------------------A2阶段-----------------------------------------------------------check
	ecurve_mult(k, G, C1);
	Point2BitString(C1, C1BitString);
	//----------------------------------------------A2阶段-----------------------------------------------------------

	//----------------------------------------------A3阶段-----------------------------------------------------------check
	ecurve_mult(h, Pk, hPK);
	if (point_at_infinity(hPK))
	{
		printf("Pk at infinity!\n");
		return;
	}
	//----------------------------------------------A3阶段-----------------------------------------------------------


	//----------------------------------------------A4阶段-----------------------------------------------------------check
	ecurve_mult(k, Pk, kPK);
	//epoint_print(kPK);
	//----------------------------------------------A4阶段-----------------------------------------------------------

	//----------------------------------------------A5阶段-----------------------------------------------------------
	epoint_get(kPK, X2, Y2);
	big_to_bytes(32, X2, (char*)x2, RightJustify);
	big_to_bytes(32, Y2, (char*)y2, RightJustify);
	for (int i = 0; i < 32; i++)
		X2andY2[i] = x2[i];
	for (int i = 32; i < 64; i++)
		X2andY2[i] = y2[i - 32];
	KDF(X2andY2, t, 64, Length);
	//----------------------------------------------A5阶段-----------------------------------------------------------


	//----------------------------------------------A6阶段-----------------------------------------------------------
	ptr = (uint8_t*)t;
	for (int i = 0; i < Length/8; i++)
	{
		C2[i] = M[i] ^ ptr[i];
	}
	//----------------------------------------------A6阶段-----------------------------------------------------------
	
	//----------------------------------------------A7阶段-----------------------------------------------------------
	for (int i = 0; i < 32; i++)
		HashInput[i] = x2[i];
	for (int i = 0; i < Length / 8; i++)
		HashInput[32 + i] = M[i];
	for (int i = 0; i < 32; i++)
		HashInput[32 + (Length / 8) + i] = y2[i];
	
	SM3(HashInput, C3, (64 + Length / 8) * 8);
	

	//----------------------------------------------A7阶段-----------------------------------------------------------
	
	//----------------------------------------------A8阶段-----------------------------------------------------------
	uint8_t* C3ptr = (uint8_t*)C3;
	for (int i = 0; i < 32; i = i + 4)
	{
		u8C3[i + 3] = C3ptr[i + 0];
		u8C3[i + 2] = C3ptr[i + 1];
		u8C3[i + 1] = C3ptr[i + 2];
		u8C3[i + 0] = C3ptr[i + 3];
	}
	//Align8Print(u8C3, 32);
	for (int i = 0; i < 65; i++)
		C[i] = C1BitString[i];
	for (int i = 0; i < 32; i++)
		C[65 + i] = u8C3[i];
	for (int i = 0; i < Length / 8; i++)
		C[65 + 32 + i] = C2[i];
	for (int i = 0; i < (65 + 32 + Length / 8); i++)
		Ciphertext[i] = C[i];
	//----------------------------------------------A8阶段-----------------------------------------------------------
	
	
	//---------------------------------------------释放内存---------------------------------------------------------
	free(C1BitString);
	free(t);
	free(C3);
	free(x2);
	free(X2andY2);
	free(C2);
	free(HashInput);
	free(C);
	free(u8C3);
	epoint_free(C1);
	epoint_free(hPK);
	epoint_free(kPK);
	mirkill(k);
	mirkill(h);
	mirkill(X2);
	mirkill(Y2);
	//---------------------------------------------释放内存---------------------------------------------------------
}

#endif


