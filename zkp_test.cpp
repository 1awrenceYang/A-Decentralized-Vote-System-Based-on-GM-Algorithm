#include <iostream>
#include "zpk.h"
int main()
{
	miracl* mip = mirsys(36, MAXBASE);
	time_t seed;
	time(&seed);
	irand((unsigned long long)seed);
	

	int m;
	cout << "Vote:";
	cin >> m;

	epoint* G, * A1, * A2, *mG;
	big challenge, m_big, response;
	challenge = mirvar(0);
	m_big = mirvar(0);
	response = mirvar(0);
	G = epoint_init();
	mG = epoint_init();
	A1 = epoint_init();
	A2 = epoint_init();
	convert(m, m_big);
	ecurve_mult(m_big, G, mG);


	/*****************************ZKP********************************/
	Prover P; 
	Verifier V;
	P.init(m);
	V.init();

	P.ProverGenA1A2(G);
	A1 = P.A1;
	V.VerifierGenChallenge();
	challenge = V.challenge;
	P.ProverGenResponse(m, challenge, G);
	response = P.response;
	V.VerifierVerify(response, G, mG, A1, A2);
}
