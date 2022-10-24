
uint32_t IV[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };//常量IV
uint32_t Tj015 = 0x79cc4519;//常量Tj 0-15的取值
uint32_t Tj1663 = 0x7a879d8a;//常量Tj 16-63的取值
unsigned long long PassLengthToPadding = 0;
#define FFj015(x,y,z) x^y^z//FFj函数0-15
#define FFj1663(x,y,z) (x&y)|(x&z)|(y&z)//FFj函数16-63
#define GGj015(x,y,z) x^y^z//GGj函数0-15
#define GGj1663(x,y,z) (x&y)|(~x&z)//GGj函数1663
#define P0(x) x^((x<<9)|(x>>23))^((x<<17)|(x>>15))//P0函数
#define P1(x) x^((x<<15)|(x>>17))^((x<<23)|(x>>9))//P1函数
#define MERAGE4(one,two,three,four)	(((uint32_t)one << 24) | ((uint32_t)two << 16) | ((uint16_t)three << 8) | four)//四个uint8合并成一个uint32
#define round_shift_left(x,n) x<<n|x>>32-n//向左循环移位
unsigned long long MODNUM = 4294967296;//2的32次方
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
unsigned int after_padding_length = 0;//填充后消息长度，单位是字节
uint8_t* padding(uint8_t* input, unsigned long long length)//length单位是比特,输入是以uint8_t数组的形式，输出padding好的uint8_t数组
{
	int k = 1;
	int total_length = (length / 512 + 1) * 512;//填充后比特长度
	int byte_length = length / 8;//填充前字节长度
	int total_byte_length = total_length / 8;//填充后字节长度
	for (k; k < total_length; k++)
	{
		if (((length + 1 + k) % 512) == 448)
			break;
	}
	uint8_t* output = (uint8_t*)malloc((total_length / 8) * sizeof(uint8_t));
	for (int i = 0; i < byte_length; i++)//首先output的前几个和input一致
	{
		output[i] = input[i];
	}

	output[byte_length] = 0x80;//赋值一个1和7个零

	int outfix = byte_length + 1 + (k - 7) / 8;//剩下的0的个数是（k-7）/8
	for (int i = byte_length + 1; i < outfix; i++)//为这些补0
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
void message_extension(uint8_t* input, uint32_t* W, uint32_t* W_1)//W是w0-w67，W_1是w0'-w63' uint32只支持输入长度是512bit以内,W和W_1传入之前必须先分配68和64个uint32_t空间
{
	int word_length = after_padding_length / 16;//消息字大小,也即一个消息字含有的uint8_t的数量
	//uint32_t* W = (uint32_t*)malloc(68 * sizeof(uint32_t));//即Wi不带'
	//uint32_t* W_1 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	for (int i = 0; i < 16; i++)
	{
		W[i] = MERAGE4(input[i * 4 + 0], input[i * 4 + 1], input[i * 4 + 2], input[i * 4 + 3]);
	}
	/*for (int i = 0; i < 16; i++)
	{
		printf("%x", W015[i]);
	}*/
	for (int i = 16; i < 68; i++)//W的计算 有68个
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
	for (int i = 0; i < 64; i++)//w'的计算，64个
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
	uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, shift_left_Ti, FF_result, GG_result;//shift_left_Ti是Ti常数向左循环移位的结果
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
void CF_1(uint32_t* Vi, uint32_t* W, uint32_t* W_1)//第一个512消息快的CF函数
{
	uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, shift_left_Ti, FF_result, GG_result;//shift_left_Ti是Ti常数向左循环移位的结果
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
void CF_2(uint32_t* Vi, uint32_t* W, uint32_t* W_1)//第一个512消息快的CF函数
{
	uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, shift_left_Ti, FF_result, GG_result;//shift_left_Ti是Ti常数向左循环移位的结果
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
void sm3(uint8_t* input, unsigned int length)//sm3哈希函数，输入仅支持512比特以内，以uint8数组形式输入,第二个参数是输入数据长度，单位是bit,函数计算完成后全局变量SM3_hash_result存储运算结果，形式是长度为8的uint32数组
{
	//uint8_t* padding_result = (uint8_t*)malloc(64 * sizeof(uint8_t));
	//padding_result = padding(input, length);
	uint32_t* W = (uint32_t*)malloc(68 * sizeof(uint32_t));//即Wi不带'
	uint32_t* W_1 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	CF(IV, input, W, W_1);
}
void Sm3_1024(uint8_t* input, unsigned int length)//输入长度超过512bit，会填充至1024bit的sm3
{
	uint32_t* W = (uint32_t*)malloc(68 * sizeof(uint32_t));//即Wi不带'
	uint32_t* W_1 = (uint32_t*)malloc(64 * sizeof(uint32_t));//Wi'
	uint32_t* W1 = (uint32_t*)malloc(68 * sizeof(uint32_t));//即Wi不带'
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
