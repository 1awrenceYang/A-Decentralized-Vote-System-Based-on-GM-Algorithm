extern "C"
{
#include<stdio.h>
#include"miracl.h"
#include<time.h>
}
#include<iostream>
#include"SM2_Param.h"
#include"sm3.h"

#include<time.h>
#pragma once
using namespace std;

class Verifier {
public:
	big challenge;
	epoint* ViryLeft,*ViryRight;

public:
	void init()
	{
		challenge = mirvar(0);
		ViryRight = epoint_init();
		ViryLeft = epoint_init();
	}
	
	void VerifierGenChallenge()
	{
		bigbits(256, challenge);
		cout << "Verifier send challenge to Prover" << endl;
	}

	void VerifierVerify(big response, epoint* G, epoint* mG, epoint* A1, epoint*A2) { //mG为C2中的[m]G
		ecurve_mult(response, G, ViryLeft);  //验证等式的左边为[response]G
		ecurve_add(A1, A2);  
		ecurve_mult(challenge, mG, ViryRight);
		ecurve_add(A2, ViryRight);  //验证等式的右边为 A1+A2+[challenge]mG

		if (ViryLeft == ViryRight) {
			cout << "Vote is validated" << endl;
		}
		else {
			cout << "Vote is unvalidated, please vote again" << endl;
		}
	}

};

class Prover {
	big a1, a2, m1, m2, challenge1, challenge2, response1, response2, 
		challenge2_mult_m2, neg_challenge2_mult_m2, neg_challenge2, 
		neg_response1, neg_challenge1, challenge1_mult_m1;
public:
	epoint* A1, * A2;
	big response;
public:
	void init(int m)
	{
		a1 = mirvar(0);
		a2 = mirvar(0);
		m1 = mirvar(0);
		m2 = mirvar(0);
		response1 = mirvar(0);
		response2 = mirvar(0);
		challenge1 = mirvar(0);
		challenge2 = mirvar(0);
		challenge1_mult_m1 = mirvar(0);
		challenge2_mult_m2 = mirvar(0);
		neg_challenge2_mult_m2 = mirvar(0);
		neg_challenge2 = mirvar(0);
		neg_response1 = mirvar(0);
		neg_challenge1 = mirvar(0);
		response = mirvar(0);

		A1 = epoint_init();
		A2 = epoint_init();

		convert(m, m1);
		convert((1 - m), m2);  //m2=1-m

	}
	void ProverGenA1A2(epoint* G )
	{
		bigbits(256, a1);  //生成随机数a1
		ecurve_mult(a1, G, A1);  //A1=[a1]G

		bigbits(128, challenge2);  //提前生成challenge2
		bigbits(128, response2);  //提起生成response2，反推出a2
		multiply(challenge2, m2, challenge2_mult_m2);  //challenge2_mult_m2 = challenge2 * m2
		negify(challenge2_mult_m2, neg_challenge2_mult_m2);
		add(response2, neg_challenge2_mult_m2, a2);  //a2 = response2 - challenge2 * m2
		ecurve_mult(a2, G, A2);  //A2=[a2]G

		cout << "Prover send A1,A2 to Verifier" << endl;
	}
	void ProverGenResponse(int m, big challenge, epoint* G)
	{	
		negify(challenge2, neg_challenge2);
		add(challenge, neg_challenge2, challenge1);  //challenge1 = challenge -challenge2
		multiply(challenge1, m1, challenge1_mult_m1);
		add(a1, challenge1_mult_m1, response1);  //response1 = a1 + challenge1 * m1
		add(response1, response2, response);  //response = response1 + response2

		cout << "Prover send reponse to Verifier" << endl;
	}
};



