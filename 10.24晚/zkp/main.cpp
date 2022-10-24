#include "SM2.h"
#include "zpk.h"
#include "voter.h"
#include <conio.h>  //控制台掩藏输入
using namespace std;


int main()
{
    miracl* mip = mirsys(36, MAXBASE);
    time_t seed;
    time(&seed);
    irand((unsigned long long)seed);
    mip->IOBASE = HexIOBASAE;


    int N = 10; //参加投票人数
    voter Voter[10];
    for (int i = 0; i < N; i++) {
        /**********************************************************/
        /*                     1. 选择投票内容                      */
        /**********************************************************/
        cout << "Voter " << i << "start voting....." << endl;
        cout << "chose your vote: 0->oppose;1->suppose:";
        char m;
        while (1) {
            m = _getch();
            if (m == '\r') break;
        }
        Voter[i].init(m);  //初始化
        

        /**********************************************************/
        /*                    2. VRF 选出leader                    */
        /**********************************************************/
        cout << "leader->1;voter->0: ";
        cin >> Voter[i].PorV;//运行VRF，Voter[i].PorV = VRF(); 这里先自行输入


        /**********************************************************/
        /*                        3. SM2加密                       */
        /**********************************************************/
        if (Voter[i].PorV == 1) {
            Voter[i].Enc();
            //if leader
            epoint* HomoC1, * HomoC2;
            HomoC1 = epoint_init();
            HomoC2 = epoint_init();
            //同态聚合所有选票
            HomoEncryption(Voter[0].c1, Voter[0].c1, Voter[1].c2, Voter[1].c2, HomoC1, HomoC2);
            for (int j = 2; j < N; j++) {
                HomoEncryption(HomoC1, HomoC2, Voter[j].c2, Voter[j].c2, HomoC1, HomoC2);
            }
        }
        else if (Voter[i].PorV == 0) {
            Voter[i].Enc();
        }
        //???加入多线程，将leader同台聚合阻塞，当所有人投完票再聚合？？？
        //？？？或者将leader换到最后？？？


        /**********************************************************/
        /*                        4.zkp                           */
        /**********************************************************/
        Voter[i].zkp(Voter[i].PorV);


        /**********************************************************/
        /*                        5.RingSign                      */
        /**********************************************************/

    }
}
