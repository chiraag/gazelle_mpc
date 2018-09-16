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
ui32 num_rows = 100, num_cols = 980, window_size = 9;
ui32 mat_window_size = 10, mat_num_windows = 2;
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
    ui32 num_windows = 1 + floor(log2(test_params.q))/test_params.window_size;

    // get up the networking
    IOService ios(0);
    Session sess(ios, addr, 1212, EpMode::Client);
    Channel chl = sess.addChannel();

    uv64 vec = get_dgg_testvector(num_cols, opt::p);

    Timer time;
    chl.resetStats();
    time.setTimePoint("start");
    // KeyGen
    auto kp = KeyGen(test_params);

    ui32 num_rot = nxt_pow2(num_rows)*nxt_pow2(num_cols)/opt::phim;
    uv32 index_list;
    for (ui32 i = 1; i < num_rot; i++){
        index_list.push_back(i);
    }
    for(ui32 i=num_rot; i<num_cols; i*=2){
        index_list.push_back(i);
    }

    EvalAutomorphismKeyGen(kp.sk, index_list, test_params);
    for(ui32 n=0; n<index_list.size(); n++){
        auto rk = g_rk_map[index_list[n]];
        for(ui32 w=0; w<num_windows; w++){
            chl.send(rk->a[w]);
            chl.send(rk->b[w]);
        }
    }

    std::cout
        << "      Sent: " << chl.getTotalDataSent() << std::endl
        << "  received: " << chl.getTotalDataRecv() << std::endl << std::endl;
    chl.resetStats();

    time.setTimePoint("setup");

    for(ui32 rep=0; rep<num_rep; rep++){
        auto ct_vec = preprocess_vec(kp.sk, vec, mat_window_size, mat_num_windows, test_params);
        for(ui32 n=0; n<ct_vec.size(); n++){
            chl.send(ct_vec[n].a);
            chl.send(ct_vec[n].b);
        }

        Ciphertext ct_prod(opt::phim);
        chl.recv(ct_prod.a);
        chl.recv(ct_prod.b);
        auto prod = postprocess_prod(kp.sk, ct_prod, num_cols, num_rows, test_params);
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
    ui32 num_windows = 1 + floor(log2(test_params.q))/test_params.window_size;

    // get up the networking
    IOService ios(0);
    Session sess(ios, addr, 1212, EpMode::Server);
    Channel chl = sess.addChannel();

    Timer time;
    time.setTimePoint("start");

    std::vector<uv64> mat(num_rows, uv64(num_cols));
    for(ui32 row=0; row<num_rows; row++){
        mat[row] = get_dgg_testvector(num_cols, opt::p);
    }
    auto enc_mat = preprocess_matrix(mat, mat_window_size, mat_num_windows, test_params);

    ui32 num_rot = nxt_pow2(num_rows)*nxt_pow2(num_cols)/opt::phim;
    uv32 index_list;
    for (ui32 i = 1; i < num_rot; i++){
        index_list.push_back(i);
    }
    for(ui32 i=num_rot; i<num_cols; i*=2){
        index_list.push_back(i);
    }

    for(ui32 n=0; n<index_list.size(); n++){
        RelinKey rk(test_params.phim, num_windows);
        for(ui32 w=0; w<num_windows; w++){
            chl.recv(rk.a[w]);
            chl.recv(rk.b[w]);
        }
        g_rk_map[index_list[n]] =std::make_shared<RelinKey>(rk);
    }

    time.setTimePoint("setup");
    for(ui32 rep=0; rep<num_rep; rep++){
        CTVec ct_vec(mat_num_windows, Ciphertext(opt::phim));
        for(ui32 n=0; n<ct_vec.size(); n++){
            chl.recv(ct_vec[n].a);
            chl.recv(ct_vec[n].b);
        }

        auto ct_prod = mat_mul_online(ct_vec, enc_mat, num_cols, test_params);
        chl.send(ct_prod.a);
        chl.send(ct_prod.b);
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
    std::cin >> num_rows >> num_cols >> window_size;

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
