
uint32_t IV[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };//����IV
uint32_t Tj015 = 0x79cc4519;//����Tj 0-15��ȡֵ
uint32_t Tj1663 = 0x7a879d8a;//����Tj 16-63��ȡֵ
unsigned long long PassLengthToPadding = 0;
#define FFj015(x,y,z) x^y^z//FFj����0-15
#define FFj1663(x,y,z) (x&y)|(x&z)|(y&z)//FFj����16-63
#define GGj015(x,y,z) x^y^z//GGj����0-15
#define GGj1663(x,y,z) (x&y)|(~x&z)//GGj����1663
#define P0(x) x^((x<<9)|(x>>23))^((x<<17)|(x>>15))//P0����
#define P1(x) x^((x<<15)|(x>>17))^((x<<23)|(x>>9))//P1����
#define MERAGE4(one,two,three,four)	(((uint32_t)one << 24) | ((uint32_t)two << 16) | ((uint16_t)three << 8) | four)//�ĸ�uint8�ϲ���һ��uint32
#define round_shift_left(x,n) x<<n|x>>32-n//����ѭ����λ
unsigned long long MODNUM = 4294967296;//2��32�η�
uint32_t SM3_hash_result[8];
void print_format_char(uint8_t* input, int length)
{
	for (int i = 0; i < length; i++)
	{
		if (input[i] >> 4 == 0)
		{
			printf("0");
			printf("%x", input[i]);
		}
		else
		{
			printf("%x", input[i]);
		}

		if (i > 0 && (i + 1) % 4 == 0)
			printf(" ");
		if ((i + 1) % 32 == 0)
			printf("\n");
	}
	printf("\n");
}
void print_format_32(uint32_t* input, int length)
{
	for (int i = 0; i < length; i++)
	{
		printf("%x", input[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
		else
			printf(" ");
	}
}
#include<cstdio>
unsigned int after_padding_length = 0;//������Ϣ���ȣ���λ���ֽ�
uint8_t* padding(uint8_t* input, unsigned long long length)//length��λ�Ǳ���,��������uint8_t�������ʽ�����padding�õ�uint8_t����
{
	int k = 1;
	int total_length = (length / 512 + 1) * 512;//������س���
	int byte_length = length / 8;//���ǰ�ֽڳ���
	int total_byte_length = total_length / 8;//�����ֽڳ���
	for (k; k < total_length; k++)
	{
		if (((length + 1 + k) % 512) == 448)
			break;
	}
	uint8_t* output = (uint8_t*)malloc((total_length / 8) * sizeof(uint8_t));
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

	uint8_t* ptr = (uint8_t*)&length;
	for (int i = 0; i < 8; i++)
	{
		uint8_t temp = *ptr;
		output[total_byte_length - i - 1] = temp;
		ptr = ptr + 1;
	}
	after_padding_length = total_byte_length;
	return output;
}
void message_extension(uint8_t* input, uint32_t* W, uint32_t* W_1)//W��w0-w67��W_1��w0'-w63' uint32ֻ֧�����볤����512bit����,W��W_1����֮ǰ�����ȷ���68��64��uint32_t�ռ�
{
	int word_length = after_padding_length / 16;//��Ϣ�ִ�С,Ҳ��һ����Ϣ�ֺ��е�uint8_t������
	//uint32_t* W = (uint32_t*)malloc(68 * sizeof(uint32_t));//��Wi����'
	//uint32_t* W_1 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	for (int i = 0; i < 16; i++)
	{
		W[i] = MERAGE4(input[i * 4 + 0], input[i * 4 + 1], input[i * 4 + 2], input[i * 4 + 3]);
	}
	/*for (int i = 0; i < 16; i++)
	{
		printf("%x", W015[i]);
	}*/
	for (int i = 16; i < 68; i++)//W�ļ��� ��68��
	{
		uint32_t Wj_16 = W[i - 16];
		uint32_t Wj_9 = W[i - 9];
		uint32_t Wj_3 = W[i - 3];
		uint32_t Wj_13 = W[i - 13];
		uint32_t Wj_6 = W[i - 6];
		uint32_t round_shift1 = round_shift_left(Wj_3, 15);
		uint32_t round_shift2 = round_shift_left(Wj_13, 7);
		uint32_t P1_input = Wj_16 ^ Wj_9 ^ round_shift1;
		uint32_t P1_result = P1(P1_input);
		W[i] = P1_result ^ round_shift2 ^ Wj_6;
	}
	/*for (int i = 0; i < 68; i++)
	{
		if (W[i] == 0)
			printf("00000000 ");
		else
			printf("%x ", W[i]);
		if (i % 4 == 0&&i!=0)
		{
			printf("\n");
		}

	}*/
	for (int i = 0; i < 64; i++)//w'�ļ��㣬64��
	{
		W_1[i] = W[i] ^ W[i + 4];
	}
	/*for (int i = 0; i < 64; i++)
	{
		printf("%x", W_1[i]);
	}*/

}
void CF(uint32_t* Vi, uint8_t* Bi, uint32_t* W, uint32_t* W_1)
{
	uint8_t* padding_result = (uint8_t*)malloc(64 * sizeof(uint8_t));
	padding_result = padding(Bi, PassLengthToPadding);
	message_extension(padding_result, W, W_1);
	uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, shift_left_Ti, FF_result, GG_result;//shift_left_Ti��Ti��������ѭ����λ�Ľ��
	A = IV[0], B = IV[1], C = IV[2], D = IV[3], E = IV[4], F = IV[5], G = IV[6], H = IV[7];
	for (int i = 0; i < 64; i++)
	{
		uint32_t A_round_shift_left_12 = round_shift_left(A, 12);
		unsigned int j_shift_left = i % 32;
		if (i <= 15)
			shift_left_Ti = round_shift_left(Tj015, j_shift_left);
		else
			shift_left_Ti = round_shift_left(Tj1663, j_shift_left);

		SS1 = (A_round_shift_left_12 + E + shift_left_Ti) % MODNUM;
		SS1 = round_shift_left(SS1, 7);
		SS2 = SS1 ^ A_round_shift_left_12;
		if (i <= 15)
		{
			FF_result = FFj015(A, B, C);
			GG_result = GGj015(E, F, G);
			TT1 = (FF_result + D + SS2 + W_1[i]) % MODNUM;
			TT2 = (GG_result + H + SS1 + W[i]) % MODNUM;
		}

		else
		{
			FF_result = FFj1663(A, B, C);
			GG_result = GGj1663(E, F, G);
			TT1 = (FF_result + D + SS2 + W_1[i]) % MODNUM;
			TT2 = (GG_result + H + SS1 + W[i]) % MODNUM;
		}
		D = C;
		C = round_shift_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = round_shift_left(F, 19);
		F = E;
		E = P0(TT2);
		//printf("%x %x %x %x %x %x %x %x \n", A, B, C, D, E, F, G, H);
	}
	SM3_hash_result[0] = A ^ IV[0];
	SM3_hash_result[1] = B ^ IV[1];
	SM3_hash_result[2] = C ^ IV[2];
	SM3_hash_result[3] = D ^ IV[3];
	SM3_hash_result[4] = E ^ IV[4];
	SM3_hash_result[5] = F ^ IV[5];
	SM3_hash_result[6] = G ^ IV[6];
	SM3_hash_result[7] = H ^ IV[7];
}
void CF_1(uint32_t* Vi, uint32_t* W, uint32_t* W_1)//��һ��512��Ϣ���CF����
{
	uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, shift_left_Ti, FF_result, GG_result;//shift_left_Ti��Ti��������ѭ����λ�Ľ��
	A = IV[0], B = IV[1], C = IV[2], D = IV[3], E = IV[4], F = IV[5], G = IV[6], H = IV[7];
	for (int i = 0; i < 64; i++)
	{
		uint32_t A_round_shift_left_12 = round_shift_left(A, 12);
		unsigned int j_shift_left = i % 32;
		if (i <= 15)
			shift_left_Ti = round_shift_left(Tj015, j_shift_left);
		else
			shift_left_Ti = round_shift_left(Tj1663, j_shift_left);

		SS1 = (A_round_shift_left_12 + E + shift_left_Ti) % MODNUM;
		SS1 = round_shift_left(SS1, 7);
		SS2 = SS1 ^ A_round_shift_left_12;
		if (i <= 15)
		{
			FF_result = FFj015(A, B, C);
			GG_result = GGj015(E, F, G);
			TT1 = (FF_result + D + SS2 + W_1[i]) % MODNUM;
			TT2 = (GG_result + H + SS1 + W[i]) % MODNUM;
		}

		else
		{
			FF_result = FFj1663(A, B, C);
			GG_result = GGj1663(E, F, G);
			TT1 = (FF_result + D + SS2 + W_1[i]) % MODNUM;
			TT2 = (GG_result + H + SS1 + W[i]) % MODNUM;
		}
		D = C;
		C = round_shift_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = round_shift_left(F, 19);
		F = E;
		E = P0(TT2);
		//printf("%x %x %x %x %x %x %x %x \n", A, B, C, D, E, F, G, H);
	}
	SM3_hash_result[0] = A ^ IV[0];
	SM3_hash_result[1] = B ^ IV[1];
	SM3_hash_result[2] = C ^ IV[2];
	SM3_hash_result[3] = D ^ IV[3];
	SM3_hash_result[4] = E ^ IV[4];
	SM3_hash_result[5] = F ^ IV[5];
	SM3_hash_result[6] = G ^ IV[6];
	SM3_hash_result[7] = H ^ IV[7];
}
void CF_2(uint32_t* Vi, uint32_t* W, uint32_t* W_1)//��һ��512��Ϣ���CF����
{
	uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, shift_left_Ti, FF_result, GG_result;//shift_left_Ti��Ti��������ѭ����λ�Ľ��
	A = Vi[0], B = Vi[1], C = Vi[2], D = Vi[3], E = Vi[4], F = Vi[5], G = Vi[6], H = Vi[7];
	for (int i = 0; i < 64; i++)
	{
		uint32_t A_round_shift_left_12 = round_shift_left(A, 12);
		unsigned int j_shift_left = i % 32;
		if (i <= 15)
			shift_left_Ti = round_shift_left(Tj015, j_shift_left);
		else
			shift_left_Ti = round_shift_left(Tj1663, j_shift_left);

		SS1 = (A_round_shift_left_12 + E + shift_left_Ti) % MODNUM;
		SS1 = round_shift_left(SS1, 7);
		SS2 = SS1 ^ A_round_shift_left_12;
		if (i <= 15)
		{
			FF_result = FFj015(A, B, C);
			GG_result = GGj015(E, F, G);
			TT1 = (FF_result + D + SS2 + W_1[i]) % MODNUM;
			TT2 = (GG_result + H + SS1 + W[i]) % MODNUM;
		}

		else
		{
			FF_result = FFj1663(A, B, C);
			GG_result = GGj1663(E, F, G);
			TT1 = (FF_result + D + SS2 + W_1[i]) % MODNUM;
			TT2 = (GG_result + H + SS1 + W[i]) % MODNUM;
		}
		D = C;
		C = round_shift_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = round_shift_left(F, 19);
		F = E;
		E = P0(TT2);
		//printf("%x %x %x %x %x %x %x %x \n", A, B, C, D, E, F, G, H);
	}
	SM3_hash_result[0] = A ^ SM3_hash_result[0];
	SM3_hash_result[1] = B ^ SM3_hash_result[1];
	SM3_hash_result[2] = C ^ SM3_hash_result[2];
	SM3_hash_result[3] = D ^ SM3_hash_result[3];
	SM3_hash_result[4] = E ^ SM3_hash_result[4];
	SM3_hash_result[5] = F ^ SM3_hash_result[5];
	SM3_hash_result[6] = G ^ SM3_hash_result[6];
	SM3_hash_result[7] = H ^ SM3_hash_result[7];
}
void sm3(uint8_t* input, unsigned int length)//sm3��ϣ�����������֧��512�������ڣ���uint8������ʽ����,�ڶ����������������ݳ��ȣ���λ��bit,����������ɺ�ȫ�ֱ���SM3_hash_result�洢����������ʽ�ǳ���Ϊ8��uint32����
{
	//uint8_t* padding_result = (uint8_t*)malloc(64 * sizeof(uint8_t));
	//padding_result = padding(input, length);
	uint32_t* W = (uint32_t*)malloc(68 * sizeof(uint32_t));//��Wi����'
	uint32_t* W_1 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	CF(IV, input, W, W_1);
}
void Sm3_1024(uint8_t* input, unsigned int length)//���볤�ȳ���512bit���������1024bit��sm3
{
	uint32_t* W = (uint32_t*)malloc(68 * sizeof(uint32_t));//��Wi����'
	uint32_t* W_1 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	uint32_t* W1 = (uint32_t*)malloc(68 * sizeof(uint32_t));//��Wi����'
	uint32_t* W_11 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	uint8_t* padding_result = (uint8_t*)malloc(128 * sizeof(uint8_t));
	uint8_t* result1 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	uint8_t* result2 = (uint8_t*)malloc(64 * sizeof(uint8_t));
	padding_result = padding(input, length);
	for (int i = 0; i < 64; i++)
	{
		result1[i] = padding_result[i];
		result2[i] = padding_result[i + 64];
	}
	message_extension(result1, W, W_1);
	message_extension(result2, W1, W_11);
	//print_format_32(W_11, 64);
	CF_1(IV, W, W_1);
	CF_2(SM3_hash_result, W1, W_11);
}
void print_sm3_result()
{
	for (int i = 0; i < 8; i++)
	{
		printf("%x ", SM3_hash_result[i]);
	}
}
