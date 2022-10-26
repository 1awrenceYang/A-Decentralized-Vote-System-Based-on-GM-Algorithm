#include "QDebugDemo.h"
#include <QDateTime>
#include <qdebug.h>
#include"SM2_Param.h"
#include"SM2.h"
#include"voter.h"
#include"zpk.h"
#include"SM2RingSig.h"
#include<chrono>
#include<string>
using namespace chrono;
void HexToAscii(unsigned char* pHex, unsigned char* pAscii, int nLen)
{
	unsigned char Nibble[2];

	for (int i = 0; i < nLen; i++)
	{
		Nibble[0] = (pHex[i] & 0xF0) >> 4;
		Nibble[1] = pHex[i] & 0x0F;
		for (int j = 0; j < 2; j++)
		{
			if (Nibble[j] < 10)
				Nibble[j] += 0x30;
			else
			{
				if (Nibble[j] < 16)
					Nibble[j] = Nibble[j] - 10 + 'A';
			}
			*pAscii++ = Nibble[j];
		}   // for (int j = ...)
	}   // for (int i = ...)
}
void QDebugDemo::PrintQtMessage(char* Message, int Length)//打印16进制数字到16进制字符串,第二个参数是输入的字节长度
{
	unsigned char* MessageWithEOF = (unsigned char*)malloc((2 * Length + 1) * sizeof(unsigned char));
	HexToAscii((unsigned char*)Message, MessageWithEOF, Length);
	MessageWithEOF[2 * Length] = 0x00;
	qInfo((const char*)MessageWithEOF);
	free(MessageWithEOF);
}
void QtPrintPoint(epoint* onPrintingPoint)
{
	big X, Y;
	char* x, * y;
	X = mirvar(0);
	Y = mirvar(0);
	x = (char*)malloc(32 * sizeof(char));
	y = (char*)malloc(32 * sizeof(char));
	epoint_get(onPrintingPoint, X, Y);
	big_to_bytes(32, X, x, RightJustify);
	big_to_bytes(32, Y, y, RightJustify);
	unsigned char* MessageWithEOF = (unsigned char*)malloc((2 * 32 + 1) * sizeof(unsigned char));
	unsigned char* MessageWithEOFy = (unsigned char*)malloc((2 * 32 + 1) * sizeof(unsigned char));
	HexToAscii((unsigned char*)x, MessageWithEOF, 32);
	HexToAscii((unsigned char*)y, MessageWithEOFy, 32);
	MessageWithEOF[64] = 0x00;
	MessageWithEOFy[64] = 0x00;
	qInfo((const char*)MessageWithEOF);
	qInfo((const char*)MessageWithEOFy);
	free(x);
	free(y);
	free(MessageWithEOF);
	free(MessageWithEOFy);
	mirkill(X);
	mirkill(Y);
}
void PrintQtDouble(double Data)
{
	string temp = to_string(Data);
	char* M = (char*)malloc(100 * sizeof(char));
	strcpy(M, temp.c_str());
	qInfo((const char*)M);
	free(M);
}
QDebugDemo::QDebugDemo(QWidget* parent)
	: QMainWindow(parent)
	, paused(true)
	, aboutToExit(false)
{
	ui.setupUi(this);
	//初始化消息处理器
	connect(MessageHandlerWrapper::get_instance(), &MessageHandlerWrapper::message, this, &QDebugDemo::logToUI);
	messageHandler = MessageHandlerWrapper::get_instance();
	qInfo("Initializing application...");

	connect(ui.pushButtonPrintSingle, &QPushButton::clicked, this, &QDebugDemo::VoteTest);
	connect(ui.pushButtonStartPrinting, &QPushButton::clicked, this, &QDebugDemo::onStartPrinting);
	connect(ui.pushButtonStopPrinting, &QPushButton::clicked, this, &QDebugDemo::onStopPrinting);

	// 消息发射线程
	printingThread = new std::thread([&] 
		{
		while (!aboutToExit) 
		{
			if (!paused) 
			{
				qDebug() << "debug message sent.";
				std::this_thread::sleep_for(std::chrono::seconds(3));
			}
		}
		});
	printingThread->detach();

	const std::pair<QtMsgType, std::string> possibleMsgTypes[] = 
	{
		{QtDebugMsg,"Debug"},
		{QtWarningMsg,"Warning"},
		{QtFatalMsg,"Fatal"},
		{QtInfoMsg,"Info"}
	};
	for (auto& pair : possibleMsgTypes) 
	{
		ui.comboBox->addItem(pair.second.c_str());
	}
}

QDebugDemo::~QDebugDemo()
{
	aboutToExit = true;
}
void QDebugDemo::VoteTest()
{
	double TotalTime = 0;
	/*************************参数声明*************************************/
	qInfo("Declearing Parameters!");
	auto startTime = std::chrono::system_clock::now();
	big a, b, p, SkByShare, q, g_x, g_y, * SecretShare, Accumulator, SigKL;
	int t, Mlength;
	int* VoteResult;
	int Number = 5;
	char* VoteMessage;
	int* VoteMessageInt;
	point HomoC1, HomoC2, PK, G, * SigPk, AccC1, AccC2, C1, C2, HomoC1Acc, HomoC2Acc;
	uint32_t* AccC3, * C3;
	uint8_t* SigBL, ** Sigai, * Lhash, ** M;
	voter* Voter;
	big k, * SigSK;
	a = mirvar(0);
	b = mirvar(0);
	p = mirvar(0);
	q = mirvar(0);
	g_x = mirvar(0);
	g_y = mirvar(0);
	auto endTime = std::chrono::system_clock::now();
	double TimeUsage = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	TotalTime = TotalTime + TimeUsage;
	qInfo("Stage Time Usage:");
	PrintQtDouble(TimeUsage);
	qInfo("Parameters Declearation Complete!");
	/*************************miracl曲线运算系统建立********************************/
	qInfo("*************************Miracl Eplitic Curve System Initilizing*************************");
	startTime = std::chrono::system_clock::now();
	bytes_to_big(32, Sm2CurveParam_a, a);
	bytes_to_big(32, Sm2CurveParam_b, b);
	bytes_to_big(32, Sm2CurveParamPrime, p);
	endTime = std::chrono::system_clock::now();
	TimeUsage = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	qInfo("SM2 Recommended Curve FP-256 a:");
	PrintQtMessage(Sm2CurveParam_a, 32);

	qInfo("SM2 Recommended Curve FP-256 b:");
	PrintQtMessage(Sm2CurveParam_b, 32);

	qInfo("SM2 Recommended Curve FP-256 p:");
	PrintQtMessage(Sm2CurveParamPrime, 32);
	ecurve_init(a, b, p, MR_BEST);
	qInfo("Stage Time Usage:");
	PrintQtDouble(TimeUsage);
	TotalTime = TotalTime + TimeUsage;
	qInfo("*************************Miracl Eplitic Curve System Initialization Complete!*************************");
	qInfo("\n");
	/*****************************变量初始化********************************/
	qInfo("*************************Initializing Parameters!*************************");
	TimeUsage = 0;
	startTime = std::chrono::system_clock::now();
	t = 3;
	Mlength = 128;
	M = (uint8_t**)malloc(Number * sizeof(uint8_t*));
	for (int i = 0; i < Number; i++)
		M[i] = (uint8_t*)malloc(128 * sizeof(uint8_t));
	Lhash = (uint8_t*)malloc(32 * sizeof(uint8_t));
	HomoC1Acc = epoint_init();
	HomoC2Acc = epoint_init();
	VoteResult = (int*)malloc(sizeof(int));
	SigKL = mirvar(0);
	SigBL = (uint8_t*)malloc(128 * sizeof(uint8_t));
	Sigai = (uint8_t**)malloc(Number * sizeof(uint8_t*));
	for (int i = 0; i < Number; i++)
		Sigai[i] = (uint8_t*)malloc(32 * sizeof(uint8_t));
	HomoC1 = epoint_init();
	HomoC2 = epoint_init();
	C1 = epoint_init();
	C2 = epoint_init();
	C3 = (uint32_t*)malloc(8 * sizeof(uint32_t));
	AccC1 = epoint_init();
	AccC2 = epoint_init();
	AccC3 = (uint32_t*)malloc(8 * sizeof(uint32_t));

	SecretShare = (big*)malloc(Number * sizeof(big));
	VoteMessage = (char*)malloc(Number * sizeof(char));
	VoteMessageInt = (int*)malloc(Number * sizeof(int));
	//测试用，随便赋值几个消息
	VoteMessage[0] = 0;
	VoteMessage[1] = 1;
	VoteMessage[2] = 0;
	VoteMessage[3] = 1;
	VoteMessage[4] = 1;

	VoteMessageInt[0] = 0;
	VoteMessageInt[1] = 1;
	VoteMessageInt[2] = 0;
	VoteMessageInt[3] = 1;
	VoteMessageInt[4] = 1;
	SkByShare = mirvar(0);
	HomoC1 = epoint_init();
	HomoC2 = epoint_init();
	PK = epoint_init();
	G = epoint_init();
	bytes_to_big(32, Sm2CurveParamG_x, g_x);
	bytes_to_big(32, Sm2CurveParamG_y, g_y);
	endTime = std::chrono::system_clock::now();
	TimeUsage = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	qInfo("SM2 Recommended Curve FP-256 G:");
	PrintQtMessage(Sm2CurveParamG_x, 32);
	PrintQtMessage(Sm2CurveParamG_y, 32);
	bytes_to_big(32, Sm2CurveParamG_Order, q);
	epoint_set(g_x, g_y, 1, G);
	startTime = std::chrono::system_clock::now();
	SigPk = (point*)malloc(Number * sizeof(point));
	SigSK = (big*)malloc(Number * sizeof(big));
	for (int i = 0; i < Number; i++)
		SigPk[i] = epoint_init();
	Voter = (voter*)malloc(Number * sizeof(voter));
	k = mirvar(0);
	endTime = std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	qInfo("Public Key Set for SM2 Ring Signature Generation:");
	for (int i = 0; i < Number; i++)//签名公钥生成
	{
		startTime = std::chrono::system_clock::now();
		SigSK[i] = mirvar(0);
		bigbits(255, k);
		copy(k, SigSK[i]);
		ecurve_mult(k, G, SigPk[i]);
		endTime = std::chrono::system_clock::now();
		TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
		big SigPKX, SigPKY;
		SigPKX = mirvar(0);
		SigPKY = mirvar(0);
		char* SigPkX = (char*)malloc(32 * sizeof(char));
		char* SigPkY = (char*)malloc(32 * sizeof(char));
		epoint_get(SigPk[i], SigPKX, SigPKY);
		big_to_bytes(32, SigPKX, SigPkX, RightJustify);
		big_to_bytes(32, SigPKY, SigPkY, RightJustify);
		PrintQtMessage(SigPkX, 32);
		PrintQtMessage(SigPkY, 32);
		free(SigPkX);
		free(SigPkY);
	}
	qInfo("Stage Time Usage:");
	TotalTime = TotalTime + TimeUsage;
	PrintQtDouble(TimeUsage);
	qInfo("*************************Parameters Initilization Complete!*************************");
	qInfo("\n");
	/*****************************秘密共享生成公钥，秘密份额****************************/
	TimeUsage = 0;
	qInfo("*************************Generating Secret Share,Secret Key and Public Key By Secret Share:*************************");
	startTime= std::chrono::system_clock::now();
	SecretShare = GenPkbySecretShare(Number, t, G, PK, q);
	endTime= std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	qInfo("Secret Share ,Secret Key,Public Key Generation Complete:");
	for (int i = 0; i < Number; i++)
	{
		char* onPrintingSecretShare = (char*)malloc(32 * sizeof(char));
		big_to_bytes(32, SecretShare[i], onPrintingSecretShare, RightJustify);
		PrintQtMessage(onPrintingSecretShare, 32);
	}
	qInfo("Public Key Generated By Secret Share:");
	QtPrintPoint(PK);
	SkByShare = GenSkBySecretShare(t, SecretShare, q);
	qInfo("Initial value of Homoencryption:");
	startTime= std::chrono::system_clock::now();
	Encryption(0, PK, G, AccC1, AccC2, AccC3);//初始聚合值是0的同态密文
	endTime= std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	char* Acc3Char = (char*)malloc(32 * sizeof(char));
	Convert(AccC3, (uint8_t*)Acc3Char);
	QtPrintPoint(AccC1);
	QtPrintPoint(AccC2);
	PrintQtMessage((char*)Acc3Char, 32);
	qInfo("Stage Time Usage:");
	TotalTime = TotalTime + TimeUsage;
	PrintQtDouble(TimeUsage);
	qInfo("*************************Generation of Public Key,Secret Key,Secrek Share Complete By Secret Share!*************************");
	qInfo("\n");
	/******************************Voter初始化******************************************/
	qInfo("*************************Voter Initilizing*************************");
	TimeUsage = 0;
	startTime = std::chrono::system_clock::now();
	for (int i = 0; i < Number; i++)
	{
		Voter[i].init(VoteMessage[i], PK, G, i);
	}
	endTime = std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	qInfo("Stage Time Usage:");
	TotalTime = TotalTime + TimeUsage;
	PrintQtDouble(TimeUsage);
	qInfo("*************************Voter Initilization Complete!*************************");
	qInfo("\n");
	/******************************投票内容加密******************************************/
	qInfo("*************************Encryptioin of Vote Message*************************");
	TimeUsage = 0;
	for (int i = 0; i < Number; i++)
	{
		big C1X, C1Y, C2X, C2Y;
		uint8_t* c1x, * c1y, * c2x, * c2y;
		C1X = mirvar(0);
		C1Y = mirvar(0);
		C2X = mirvar(0);
		C2Y = mirvar(0);
		c1x = (uint8_t*)malloc(32 * sizeof(uint8_t));
		c1y = (uint8_t*)malloc(32 * sizeof(uint8_t));
		c2x = (uint8_t*)malloc(32 * sizeof(uint8_t));
		c2y = (uint8_t*)malloc(32 * sizeof(uint8_t));
		startTime = std::chrono::system_clock::now();
		Encryption(VoteMessageInt[i], PK, G, C1, C2, C3);
		endTime = std::chrono::system_clock::now();
		TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
		epoint_get(C1, C1X, C1Y);
		epoint_get(C2, C2X, C2Y);
		qInfo("Encryption Ciphetext:");
		QtPrintPoint(C1);
		QtPrintPoint(C2);
		char* C3Char = (char*)malloc(32 * sizeof(char));
		Convert(C3, (uint8_t*)C3Char);
		PrintQtMessage((char*)C3Char, 32);
		big_to_bytes(32, C1X, (char*)c1x, RightJustify);
		big_to_bytes(32, C1Y, (char*)c1y, RightJustify);
		big_to_bytes(32, C2X, (char*)c2x, RightJustify);
		big_to_bytes(32, C2Y, (char*)c2x, RightJustify);
		for (int j = 0; j < 32; j++)
			M[i][j] = c1x[i];
		for (int j = 0; j < 32; j++)
			M[i][j + 32] = c1y[i];
		for (int j = 0; j < 32; j++)
			M[i][j + 64] = c2x[i];
		for (int j = 0; j < 32; j++)
			M[i][j + 96] = c2y[i];
		epoint_copy(C1, Voter[i].c1);
		epoint_copy(C2, Voter[i].c2);
		for (int j = 0; j < 8; j++)
			Voter[i].c3[j] = C3[j];
		/*epoint_print(AccC1);
		epoint_print(AccC2);*/
		try
		{
			startTime = std::chrono::system_clock::now();
			HomoEncryption(C1, AccC1, C2, AccC2, HomoC1Acc, HomoC2Acc);
			endTime = std::chrono::system_clock::now();
			TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
			epoint_copy(HomoC1Acc, AccC1);
			epoint_copy(HomoC2Acc, AccC2);
			qInfo("HomoEncryption Ciphertext:");
			QtPrintPoint(AccC1);
			QtPrintPoint(AccC2);
			printf("\n");
		}
		catch (int error)
		{
			PrintErrorMessage(error);
		}

	}
	qInfo("Stage Time Usage:");
	PrintQtDouble(TimeUsage);
	TotalTime = TotalTime + TimeUsage;
	qInfo("*************************Encryptioin of Vote Message Complete*************************");
	qInfo("\n");

	/******************************zkp******************************************/
	qInfo("*************************ZKP begin*************************");
	TimeUsage = 0;
	for (int i = 0; i < Number - 1; i++) {

		printf("......Voter [%d] start zkp......\n", i);
		//zkp init
		epoint* zkp_G, * A1, * A2, * mG;
		big challenge, m_big, response;
		challenge = mirvar(0);
		m_big = mirvar(0);
		response = mirvar(0);
		zkp_G = epoint_init();
		mG = epoint_init();
		A1 = epoint_init();
		A2 = epoint_init();
		convert(VoteMessageInt[i], m_big);
		ecurve_mult(m_big, zkp_G, mG);
		char* ChallengeChar = (char*)malloc(32 * sizeof(char));
		char* ResponseChar = (char*)malloc(64 * sizeof(char));
		Prover P;
		Verifier V;
		P.init(VoteMessageInt[i]);
		V.init();
		startTime= std::chrono::system_clock::now();
		P.ProverGenA1A2(zkp_G);
		A1 = P.A1; A2 = P.A2;
		V.VerifierGenChallenge();
		challenge = V.challenge;
		P.ProverGenResponse(VoteMessageInt[i], challenge, zkp_G);
		endTime= std::chrono::system_clock::now();
		TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
		big_to_bytes(32, challenge, ChallengeChar, RightJustify);
		
		response = P.response;
		big_to_bytes(64, response, ResponseChar, RightJustify);
		qInfo("ZKP Challenge");
		PrintQtMessage(ChallengeChar, 32);
		qInfo("ZKP Response");
		PrintQtMessage(ResponseChar, 64);
		startTime = std::chrono::system_clock::now();
		V.VerifierVerify(response, zkp_G, mG, A1, A2);
		endTime = std::chrono::system_clock::now();
		TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
		printf("......Voter [%d] finish zkp......\n", i);
		free(ChallengeChar);
		free(ResponseChar);
	}
	qInfo("Stage Time Usage:");
	PrintQtDouble(TimeUsage);
	TotalTime = TotalTime + TimeUsage;
	qInfo("*************************ZKP end*************************");
	qInfo("\n");
	/******************************环签名******************************************/
	qInfo("*************************SM2 RingSignature Generation*************************");
	TimeUsage = 0;
	big KL = mirvar(0);
	char* RandomKL = (char*)malloc(32 * sizeof(char));
	startTime = std::chrono::system_clock::now();
	KL = SM2RingSigGen(G, SigPk, SigSK[2], SigBL, Sigai, M[2], Number, 2, Mlength, Lhash);
	endTime = std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();

	big_to_bytes(32, KL, RandomKL, RightJustify);
	qInfo("Random Number KL:");
	PrintQtMessage(RandomKL, 32);
	qInfo("BL:");
	PrintQtMessage((char*)SigBL, 128);
	qInfo("ai:");
	for (int i = 0; i < Number; i++)
		PrintQtMessage((char*)Sigai[i], 32);
	qInfo("L Hash Value:");
	PrintQtMessage((char*)Lhash, 32);
	startTime = std::chrono::system_clock::now();
	bool SigVerfResult = SM2RingSigProof(G, SigPk, SigBL, Sigai, M[2], Number, 2, Mlength, KL);
	endTime = std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	if (SigVerfResult = true)
		qInfo("SM2 Ring Signature Verfication Passed!");
	else
		qInfo("SM2 Ring Signature Verification Failed!");
	qInfo("Stage Time Usage:");
	PrintQtDouble(TimeUsage);
	TotalTime = TotalTime + TimeUsage;
	qInfo("*************************SM2 RingSignature Generation Complete*************************");
	qInfo("\n");
	/******************************开票******************************************/
	TimeUsage = 0;
	qInfo("*************************HomoDecryption begin*************************");
	startTime = std::chrono::system_clock::now();
	HomoDecryption(AccC1, AccC2, G, SkByShare, VoteResult);
	endTime = std::chrono::system_clock::now();
	TimeUsage = TimeUsage + std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
	char* FinalResult = (char*)malloc(2 * sizeof(char));
	FinalResult[0] = 48 + *VoteResult;
	FinalResult[1] = 0x00;
	if (*VoteResult >= 3)
	{
		qInfo("Vote Pass! Vote Pass Num:");
		qInfo((const char*)FinalResult);
	}
	else
	{
		qInfo("Vote Not Pass! Vote Pass Num:");
		qInfo((const char*)FinalResult);
	}
	qInfo("Stage Time Usage:");
	PrintQtDouble(TimeUsage);
	TotalTime = TotalTime + TimeUsage;
	qInfo("*************************HomoDecryption end*************************");
	qInfo("\n");
	qInfo("Total Time Cost(microseconds):");
	PrintQtDouble(TotalTime);
}
void QDebugDemo::onStartPrinting()
{
	paused = false;
}

void QDebugDemo::onStopPrinting()
{
	paused = true;
}

void QDebugDemo::onPrintingSingleMsg()
{
	const std::pair<QtMsgType, std::string> possibleMsgTypes[] = 
	{
		{QtDebugMsg,"Debug"},
		{QtWarningMsg,"Warning"},
		{QtFatalMsg,"Fatal"},
		{QtInfoMsg,"Info"}
	};
	logToUI(possibleMsgTypes[ui.comboBox->currentIndex()].first, "single message!");
}

void QDebugDemo::logToUI(QtMsgType type, QString msg)
{
	static QMutex mut;
	QMutexLocker lock(&mut);
	QString text;
	text.append(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + " ");
	switch (type)
	{
	case QtDebugMsg:
		text.append(" [DEBUG] ");
		break;

	case QtWarningMsg:
		text.append(" [WARNING] ");
		break;

	case QtCriticalMsg:
		text.append(" [CRITICAL] ");
		break;

	case QtFatalMsg:
		text.append(" [FATAL] ");
		break;

	case QtInfoMsg:
		text.append(" [INFO] ");
		break;
	}

	text.append(msg);
	ui.textBrowser->append(text);
}
