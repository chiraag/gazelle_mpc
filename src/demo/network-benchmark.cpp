/*
 * gc-online.cpp
 *
 *  Created on: Nov 28, 2017
 *      Author: chiraag
 */

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "utils/network.h"

using namespace osuCrypto;

std::string addr = "localhost";

void sender(){
    setThreadName("Sender");

    // get up the networking
    IOService ios(0);
    Session sess(ios, addr, 1212, EpMode::Client);
    Channel chl = sess.addChannel();

    senderGetLatency(chl);

    chl.close();
    sess.stop();
    ios.stop();
    return;
}

void receiver(){
    setThreadName("Receiver");

    // get up the networking
    IOService ios(0);
    Session sess(ios, addr, 1212, EpMode::Server);
    Channel chl = sess.addChannel();

    recverGetLatency(chl);

    chl.close();
    sess.stop();
    ios.stop();
    return;
}

int main(int argc, char** argv) {
    if (argc == 1)
    {
        std::vector<std::thread> thrds(2);
        thrds[0] = std::thread([]() { sender(); });
        thrds[1] = std::thread([]() { receiver(); });

        for (auto& thrd : thrds)
            thrd.join();
    }
    else if(argc == 2)
    {
        int role = atoi(argv[1]); // 0: send, 1: recv
        role ? receiver() : sender();
    }
    else
    {
        std::cout << "this program takes a runtime argument.\n\n"
            << "to run the AES GC, run\n\n"
            << "    gc-online [0|1]\n\n"
            << "the optional {0,1} argument specifies in which case the program will\n"
            << "run between two terminals, where each one was set to the opposite value. e.g.\n\n"
            << "    gc-online 0\n\n"
            << "    gc-online 1\n\n"
            << "These programs are fully networked and try to connect at localhost:1212.\n"
            << std::endl;
    }
}



