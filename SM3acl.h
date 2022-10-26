#ifndef SM3_ACL_H
#define SM3_ACL_H
#include<stdio.h>
#include"SM3def.h"
#include<stdlib.h>
#include<string.h>
void Align8Print(uint8_t* text, unsigned int length)//�����ֽڳ���
{
	for (int i = 0; i < length; i++)
	{
		printf("%02X", text[i]);
		if ((i + 1) % 4 == 0)
			printf(" ");
		if ((i + 1) % 32 == 0)
			printf("\n");
	}
	printf("\n");
}
void PrintSM3(uint32_t* sm3)
{
	for (int i = 0; i < 8; i++)
	{
		printf("%08X ", sm3[i]);
	}
	printf("\n");
}
unsigned long long padding(uint8_t* input, uint8_t* Out, unsigned long long length)//length��λ�Ǳ���,��������uint8_t�������ʽ�����padding�õ�uint8_t����
{
	int k = 1;
	int total_length = (length / 512 + 1) * 512;//������س���
	int byte_length = length / 8;//���ǰ�ֽڳ���
	int total_byte_length = total_length / 8;//�����ֽڳ���
	uint8_t* output = (uint8_t*)malloc((total_length / 8) * sizeof(uint8_t));
	for (k; k < total_length; k++)
	{
		if (((length + 1 + k) % 512) == 448)
			break;
	}
	for (int i = 0; i < byte_length; i++)//����output��ǰ������inputһ��
	{
		output[i] = input[i];
	}

	output[byte_length] = 0x80;//��ֵһ��1��7����

	int outfix = byte_length + 1 + (k - 7) / 8;//ʣ�µ�0�ĸ����ǣ�k-7��/8
	for (int i = byte_length + 1; i < outfix; i++)//Ϊ��Щ��0
	{
		output[i] = 0x00;
	}
	int re = 0;
	bool bin[64] = { 0 };
	int c = 0;
	int value = 0;
	while (length != 0)
	{
		re = length % 2;
		bin[63 - c] = re;
		c++;
		length = length / 2;
	}
	for (int i = 0; i < 64; i = i + 8)
	{
		value = 128 * bin[i] + 64 * bin[i + 1] + 32 * bin[i + 2] + 16 * bin[i + 3] + 8 * bin[i + 4] + 4 * bin[i + 5] + 2 * bin[i + 6] + bin[i + 7];
		output[total_byte_length - 8 + (i / 8)] = value;
	}
	for (int i = 0; i < total_byte_length; i++)
		Out[i] = output[i];
	free(output);
	return total_length;
}
void PrintW(uint32_t** W, int BlockNum, int choice)
{
	if (choice == FlagForW)
	{
		for (int i = 0; i < BlockNum; i++)
		{
			printf("W for Block %d:\n", i);
			for (int j = 0; j < 68; j++)
			{
				printf("%08x ", W[i][j]);
				if ((j + 1) % 8 == 0)
				{
					printf("\n");
				}
			}
			printf("\n");
		}
	}
	else if (choice == FlagForW1)
	{

		for (int i = 0; i < BlockNum; i++)
		{
			printf("W' for Block %d:\n", i);
			for (int j = 0; j < 64; j++)
			{
				printf("%08x ", W[i][j]);
				if ((j + 1) % 8 == 0)
				{
					printf("\n");
				}
			}
			printf("\n");
		}
	}
}
uint32_t** AllocW(int length, int choice)//������Ϣ��������ѡ���ӣ�����W��W1�ķ���õ��ڴ�
{
	uint32_t** W = (uint32_t**)malloc(length * sizeof(uint32_t**));
	if (choice == FlagForW)
	{
		for (int i = 0; i < length; i++)
			W[i] = (uint32_t*)malloc(68 * sizeof(uint32_t));

	}
	else if (choice == FlagForW1)
	{
		for (int i = 0; i < length; i++)
			W[i] = (uint32_t*)malloc(64 * sizeof(uint32_t));
	}
	return W;
}
void MessageExtension(uint8_t* B, uint32_t** OutW, uint32_t** OutW_1, unsigned long long Length)//Length����չ����Ϣ���bit����
{
	uint32_t Wj_16;
	uint32_t Wj_9;
	uint32_t Wj_3;
	uint32_t Wj_13;
	uint32_t Wj_6;
	uint32_t RoundShift1;
	uint32_t RoundShift2;
	uint32_t P1_Input;
	uint32_t P1_Output;
	unsigned int BlockNum = Length / 512;//��Ϣ��ĸ���������ȷ��W��W_1�ĳ���
	//-------------------------------------------����ռ�-------------------------------------------
	uint32_t** W = (uint32_t**)malloc(BlockNum * sizeof(uint32_t*));
	for (int i = 0; i < BlockNum; i++)
	{
		W[i] = (uint32_t*)malloc(68 * sizeof(uint32_t));
	}
	uint32_t** W_1 = (uint32_t**)malloc(BlockNum * sizeof(uint32_t*));
	for (int i = 0; i < BlockNum; i++)
	{
		W_1[i] = (uint32_t*)malloc(64 * sizeof(uint32_t));
	}
	//-------------------------------------------����ռ�-------------------------------------------

	//------------------------------------------��ʼW1-W16��ֵ-----------------------------------------------
	for (int i = 0; i < BlockNum; i++)
	{
		for (int j = 0; j < 64; j = j + 4)
		{
			W[i][j / 4] = MERAGE4(B[i * 64 + j], B[i * 64 + j + 1], B[i * 64 + j + 2], B[i * 64 + j + 3]);
		}
	}
	//------------------------------------------��ʼW1-W16��ֵ----------------------------------------------------

	//------------------------------------------����------------------------------------------------------------
	for (int i = 0; i < BlockNum; i++)
	{
		for (int j = 16; j < 68; j++)
		{
			Wj_16 = W[i][j - 16];
			Wj_9 = W[i][j - 9];
			Wj_3 = W[i][j - 3];
			Wj_13 = W[i][j - 13];
			Wj_6 = W[i][j - 6];
			RoundShift1 = round_shift_left(Wj_3, 15);
			RoundShift2 = round_shift_left(Wj_13, 7);
			P1_Input = Wj_16 ^ Wj_9 ^ RoundShift1;
			P1_Output = P1(P1_Input);
			W[i][j] = P1_Output ^ RoundShift2 ^ Wj_6;
		}
	}
	for (int i = 0; i < BlockNum; i++)
	{
		for (int j = 0; j < 64; j++)
		{
			W_1[i][j] = W[i][j] ^ W[i][j + 4];
		}
	}
	//------------------------------------------����------------------------------------------------------------

	//------------------------------------------���ؽ��-----------------------------------------------------
	for (int i = 0; i < BlockNum; i++)
	{
		for (int j = 0; j < 68; j++)
		{
			OutW[i][j] = W[i][j];
		}
	}
	for (int i = 0; i < BlockNum; i++)
	{
		for (int j = 0; j < 64; j++)
		{
			OutW_1[i][j] = W_1[i][j];
		}
	}
	free(W);
	free(W_1);
	//------------------------------------------���ؽ��-----------------------------------------------------
}
uint32_t GetTj(int j)
{
	if (j <= 15)
	{
		return Tj015;
	}
	else
	{
		return Tj1663;
	}
}
uint32_t GetFFj(uint32_t A, uint32_t B, uint32_t C, int j)
{
	if (j <= 15)
	{
		return FFj015(A, B, C);
	}
	else
	{
		return FFj1663(A, B, C);
	}
}
uint32_t GetGGj(uint32_t A, uint32_t B, uint32_t C, int j)
{
	if (j <= 15)
	{
		return GGj015(A, B, C);
	}
	else
	{
		return GGj1663(A, B, C);
	}
}
void CompressFunction(uint32_t* Vi, uint32_t* W, uint32_t* W_1, uint32_t* Vi1)
{
	uint32_t SS1, SS2, TT1, TT2;//�м����
	uint32_t A, B, C, D, E, F, G, H;//�ּĴ���
	uint32_t A_12 = 0, T_j = 0, F_19 = 0, P0_output = 0, FFj_result = 0, GGj_reulst = 0;;
	A = Vi[0];
	B = Vi[1];
	C = Vi[2];
	D = Vi[3];
	E = Vi[4];
	F = Vi[5];
	G = Vi[6];
	H = Vi[7];
	for (int i = 0; i < 64; i++)
	{
		//printf("%02d      %08X %08X %08X %08X %08X %08X %08X %08X\n", i - 1, A, B, C, D, E, F, G, H);
		A_12 = round_shift_left(A, 12);
		T_j = GetTj(i);
		T_j = round_shift_left(T_j, (i % 32));
		SS1 = round_shift_left((A_12 + E + T_j) % MODNUM, 7);
		SS2 = SS1 ^ A_12;
		FFj_result = GetFFj(A, B, C, i);
		GGj_reulst = GetGGj(E, F, G, i);
		TT1 = FFj_result + D + SS2 + W_1[i];
		TT2 = GGj_reulst + H + SS1 + W[i];
		D = C;
		C = round_shift_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = round_shift_left(F, 19);
		F = E;
		E = P0(TT2);

	}
	//("%02d      %08X %08X %08X %08X %08X %08X %08X %08X\n", 62, A, B, C, D, E, F, G, H);
	Vi1[0] = A ^ Vi[0];
	Vi1[1] = B ^ Vi[1];
	Vi1[2] = C ^ Vi[2];
	Vi1[3] = D ^ Vi[3];
	Vi1[4] = E ^ Vi[4];
	Vi1[5] = F ^ Vi[5];
	Vi1[6] = G ^ Vi[6];
	Vi1[7] = H ^ Vi[7];

}
void SM3(uint8_t* InputMessage, uint32_t* SM3Result, unsigned long long Length)//����hash���ݣ��Լ����ݵ�bit����
{
	//-----------------------------------------------��Ϣ���׶�-------------------------------------------------------
	int total_length = (Length / 512 + 1) * 512;//������س���
	int byte_length = total_length / 8;
	uint8_t* PaddingResult = (uint8_t*)malloc(byte_length * sizeof(uint8_t));
	unsigned long long AfterPaddingLength = padding(InputMessage, PaddingResult, Length);
	unsigned int BlockNum = total_length / 512;//��Ϣ������
	//-----------------------------------------------��Ϣ���׶�-------------------------------------------------------
	//��Ϣ���׶ν�����PaddingResult�����������������һ������Ϊ512bit��������uint8_t������



	//---------------------------------------------��Ϣ��չ�׶�-----------------------------------------------------------
	uint32_t** W = AllocW(BlockNum, FlagForW);//������Ϣ�ֿռ䣬��ʽ����Ϣ������*68��64�Ķ�άuint32_t����
	uint32_t** W_1 = AllocW(BlockNum, FlagForW1);
	MessageExtension(PaddingResult, W, W_1, total_length);
	//---------------------------------------------��Ϣ��չ�׶�-----------------------------------------------------------
	//��Ϣ��չ�׶ν�����W��W_1��������Ϣ��չ�������ʽ�ֱ�����Ϣ������*68����Ϣ������*64��С�Ķ�άuint32_t���飬������ѡ����Ϣ�飬������ѡ���Ӧ��Ϣ�����Ϣ��



	//---------------------------------------------ѹ�������׶�------------------------------------------------------------
	uint32_t* Vi1 = (uint32_t*)malloc(8 * sizeof(uint32_t));
	uint32_t* Vi = (uint32_t*)malloc(8 * sizeof(uint32_t));
	for (int i = 0; i < 8; i++)
	{
		Vi1[i] = 0;
		Vi[i] = 0;
	}
	for (int i = 0; i < BlockNum; i++)
	{
		if (i == 0)
		{
			//printf("��%d��ѹ������:\n", i+1);
			CompressFunction(IV, W[0], W_1[0], Vi1);//������ʼʱ��V0��ֵ��IV
			for (int i = 0; i < 8; i++)
				Vi[i] = Vi1[i];
		}
		else
		{
			//printf("��%d��ѹ������:\n", i+1);
			CompressFunction(Vi, W[i], W_1[i], Vi1);
			for (int i = 0; i < 8; i++)
				Vi[i] = Vi1[i];
		}
	}
	//---------------------------------------------ѹ�������׶�------------------------------------------------------------


	for (int i = 0; i < 8; i++)//�������
		SM3Result[i] = Vi[i];

}

















#endif 