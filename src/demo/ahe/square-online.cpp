/*
 * gc-online.cpp
 *
 *  Created on: Nov 28, 2017
 *      Author: chiraag
 */

#include <iostream>
#include <random>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <pke/gazelle.h>
#include <utils/backend.h>

#include "math/bit_twiddle.h"

using namespace lbcrypto;
using namespace osuCrypto;

std::string addr = "localhost";
ui32 vec_size = 2048, window_size = 9;
ui32 num_rep = 100;

void ahe_client(){
    std::cout << "Client" << std::endl;

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);
    FVParams test_params {
        true,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        window_size
    };

    // get up the networking
    IOService ios(0);
    Session sess(ios, addr, 1212, EpMode::Client);
    Channel chl = sess.addChannel();

    Timer time;
    chl.resetStats();
    time.setTimePoint("start");
    // KeyGen
    auto kp = KeyGen(test_params);
    uv64 vec_c = get_dgg_testvector(vec_size, opt::p);


    std::cout
        << "      Sent: " << chl.getTotalDataSent() << std::endl
        << "  received: " << chl.getTotalDataRecv() << std::endl << std::endl;
    chl.resetStats();

    time.setTimePoint("setup");

    for(ui32 rep=0; rep<num_rep; rep++){
        auto ct_vec = preprocess_client_share(kp.sk, vec_c, test_params);
        for(ui32 n=0; n<ct_vec.size(); n++){
            chl.send(ct_vec[n].a);
            chl.send(ct_vec[n].b);
        }

        Ciphertext ct_c_f(opt::phim);
        chl.recv(ct_c_f.a);
        chl.recv(ct_c_f.b);
        auto vec_c_f = postprocess_client_share(kp.sk, ct_c_f, vec_size, test_params);
    }

    std::cout
        << "      Sent: " << chl.getTotalDataSent() << std::endl
        << "  received: " << chl.getTotalDataRecv() << std::endl << std::endl;
    chl.resetStats();

    time.setTimePoint("online");

    std::cout << time << std::endl;

    chl.close();
    sess.stop();
    ios.stop();
    return;
}

void ahe_server(){
    std::cout << "Server" << std::endl;

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);
    FVParams test_params {
        true,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        window_size
    };

    // get up the networking
    IOService ios(0);
    Session sess(ios, addr, 1212, EpMode::Server);
    Channel chl = sess.addChannel();

    Timer time;
    time.setTimePoint("start");

    uv64 vec_s = get_dgg_testvector(vec_size, opt::p);

    time.setTimePoint("setup");
    for(ui32 rep=0; rep<num_rep; rep++){
        std::vector<uv64> pt_vec;
        uv64 vec_s_f;
        std::tie(pt_vec, vec_s_f) = preprocess_server_share(vec_s, test_params);

        CTVec ct_vec(2, Ciphertext(opt::phim));
        for(ui32 n=0; n<ct_vec.size(); n++){
            chl.recv(ct_vec[n].a);
            chl.recv(ct_vec[n].b);
        }

        auto ct_c_f = square_online(ct_vec, pt_vec, test_params);
        chl.send(ct_c_f.a);
        chl.send(ct_c_f.b);
    }
    time.setTimePoint("online");

    std::cout << time << std::endl;
    // std::cout << input_bits << std::endl;
    // std::cout << extractedMap << std::endl;

    chl.close();
    sess.stop();
    ios.stop();
    return;
}

int main(int argc, char** argv) {
    // std::cin >> vec_size >> window_size;

    ftt_precompute(opt::z, opt::q, opt::logn);
    ftt_precompute(opt::z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);
    precompute_automorph_index(opt::phim);

    if (argc == 1)
    {
        std::vector<std::thread> thrds(2);
        thrds[0] = std::thread([]() { ahe_server(); });
        thrds[1] = std::thread([]() { ahe_client(); });

        for (auto& thrd : thrds)
            thrd.join();
    }
    else if(argc == 2)
    {
        int role = atoi(argv[1]); // 0: send, 1: recv
        role ? ahe_server() : ahe_client();
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
