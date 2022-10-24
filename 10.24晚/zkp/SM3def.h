#ifndef SM3_DEF_H
#define SM3_DEF_H
#include<stdint.h>
uint32_t IV[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };//常量IV
uint32_t Tj015 = 0x79cc4519;//常量Tj 0-15的取值
uint32_t Tj1663 = 0x7a879d8a;//常量Tj 16-63的取值
#define FlagForW 1 //当作是W和W'的Flag即可
#define FlagForW1 0
#define FFj015(x,y,z) x^y^z//FFj函数0-15
#define FFj1663(x,y,z) (x&y)|(x&z)|(y&z)//FFj函数16-63
#define GGj015(x,y,z) x^y^z//GGj函数0-15
#define GGj1663(x,y,z) (x&y)|(~x&z)//GGj函数1663
#define P0(x) x^((x<<9)|(x>>23))^((x<<17)|(x>>15))//P0函数
#define P1(x) x^((x<<15)|(x>>17))^((x<<23)|(x>>9))//P1函数
#define MERAGE4(one,two,three,four)	(((uint32_t)one << 24) | ((uint32_t)two << 16) | ((uint16_t)three << 8) | four)//四个uint8合并成一个uint32
#define round_shift_left(x,n) x<<n|x>>32-n//向左循环移位
unsigned long long MODNUM = 4294967296;//2的32次方
#endif

