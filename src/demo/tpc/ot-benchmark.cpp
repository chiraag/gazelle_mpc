#include <iostream>
#include <numeric>

//using namespace std;
#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;

#include <cryptoTools/gsl/span>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include <ot/sr_base_ot.h>
#include <ot/cot_recv.h>
#include <ot/cot_send.h>

u64 baseCount = 128;
u64 numOTs = 1 << 24;

void iknp_recv(void)
{
    setThreadName("Receiver");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    BitVector choice(numOTs);
    choice.randomize(prng0);
    SRBaseOT send;
    IKNPReceiver r;
    std::vector<std::array<block, 2>> baseSend(baseCount);
    std::vector<block> msgs(numOTs);

    // get up the networking
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, EpMode::Server, name);
    Channel chl = ep0.addChannel(name, name);

    send.send(baseSend, prng0, chl);
    r.setBaseOts(baseSend);

    r.receive(choice, msgs, prng0, chl);

    /*for(u64 n=0; n<numOTs; n++){
        std::cout << "rx: "<< choice[n] << " " << msgs[n] << std::endl;
    }*/

    chl.close();

    ep0.stop();
    ios.stop();
}

void iknp_send(void)
{
    setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    // get up the networking
    std::string name = "n";
    IOService ios(0);
    Session  ep0(ios, "localhost", 1212, EpMode::Client, name);
    Channel chl = ep0.addChannel(name, name);

    std::vector<std::array<block, 2>> msgs(numOTs);
    for(u64 n=0; n<numOTs; n++){
        msgs[n][0] = ZeroBlock;
        msgs[n][1] = OneBlock;
    }
    std::vector<block> baseRecv(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);
    SRBaseOT base_ot;
    IKNPSender s;

    Timer time;


    time.setTimePoint("start");
    base_ot.receive(baseChoice, baseRecv, prng0, chl);
    s.setBaseOts(baseRecv, baseChoice);

    time.setTimePoint("base");
    s.send(msgs, prng0, chl);


    /*for(u64 n=0; n<numOTs; n++){
        std::cout << "tx: "<< (msgs[n][0]) << " " << (msgs[n][1]) << std::endl;
    }*/

    time.setTimePoint("finish");
    std::cout << time << std::endl;

    chl.close();

    ep0.stop();
    ios.stop();
}

int main(int argc, char** argv)
{
    std::cin >> numOTs;
    if (argc == 1)
    {
        std::vector<std::thread> thrds(2);
        thrds[0] = std::thread([]() { iknp_send(); });
        thrds[1] = std::thread([]() { iknp_recv(); });

        for (auto& thrd : thrds)
            thrd.join();
    }
    else if(argc == 2)
    {
        int role = atoi(argv[1]); // 0: send, 1: recv
        role ? iknp_recv() : iknp_send();
    }
    else
    {
        std::cout << "this program takes a runtime argument.\n\n"
            << "to run the IKNP passive secure 1-out-of-2 OT, run\n\n"
            << "    frontend.exe [0|1]\n\n"
            << "the optional {0,1} argument specifies in which case the program will\n"
            << "run between two terminals, where each one was set to the opposite value. e.g.\n\n"
            << "    frontend.exe 0\n\n"
            << "    frontend.exe 1\n\n"
            << "These programs are fully networked and try to connect at localhost:1212.\n"
            << std::endl;
    }

    return 0;
}
