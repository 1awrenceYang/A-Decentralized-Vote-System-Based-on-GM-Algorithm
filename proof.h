extern "C"
{
#include<stdio.h>
#include"miracl.h"
#include<time.h>
}
#include<iostream>
#include"SM2_Param.h"
#include"SM2.h"

#include"sm3.h"
#include<time.h>
#pragma once
using namespace std;
void proof(epoint G, big k, epoint* pks, uint8_t* BK, uint8_t** AL, unsigned int m, unsigned int L) {
	epoint* b = epoint_init();
	big x, y;
	uint8_t* BK_1;
	x = mirvar(0);
	y = mirvar(0);
	ecurve_mult(k, &G, b);
	int ia = epoint_get(b, x, y);
	int Length_x = big_to_bytes(MaxBitLength, x, (char*)BK_1, RightJustify);

}
