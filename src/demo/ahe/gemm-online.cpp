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
ui32 num_rep = 2;
ui32 window_size = 20;
ui32 n1_n3 = 128, n2 = 128;
ui32 num_rows_s = n1_n3, num_cols_s = n2;
ui32 num_rows_c = n2, num_cols_c = n1_n3;
ui32 mat_window_size = 20, mat_num_windows = 1;


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

    std::vector<uv64> mat_c(num_rows_c, uv64(num_cols_c));
    for(ui32 row=0; row<num_rows_c; row++){
        mat_c[row] = get_dgg_testvector(num_cols_c, opt::p);
    }

    for(ui32 rep=0; rep<num_rep; rep++){
        Timer time;
        chl.resetStats();
        time.setTimePoint("start");
        // KeyGen
        auto kp = KeyGen(test_params);

        ui32 rows_per_ct = test_params.phim/num_cols_c;
        uv32 index_list;
        for (ui32 i = 1; i < rows_per_ct; i++){
            index_list.push_back(test_params.phim-i*num_cols_c);
        }

        EvalAutomorphismKeyGen(kp.sk, index_list, test_params);
        for(ui32 n=0; n<index_list.size(); n++){
            auto rk = g_rk_map[index_list[n]];
            for(ui32 w=0; w<num_windows; w++){
                chl.send(rk->a[w]);
                chl.send(rk->b[w]);
            }
        }

        if(rep == 0) {
            std::cout
                << "      Sent: " << chl.getTotalDataSent() << std::endl
                << "  received: " << chl.getTotalDataRecv() << std::endl << std::endl;
        }
        chl.resetStats();

        time.setTimePoint("setup");

        auto ct_mat_c = preprocess_gemm_c(kp.sk, mat_c, mat_window_size, mat_num_windows, test_params);
        for(ui32 n=0; n<ct_mat_c.size(); n++){
            for(ui32 m=0; m<ct_mat_c[0].size(); m++){
                chl.send(ct_mat_c[n][m].a);
                chl.send(ct_mat_c[n][m].b);
            }
        }

        CTVec ct_prod(num_rows_s/rows_per_ct, Ciphertext(opt::phim));
        for(ui32 n=0; n<ct_prod.size(); n++){
            chl.recv(ct_prod[n].a);
            chl.recv(ct_prod[n].b);
        }

        auto prod = postprocess_gemm(kp.sk, ct_prod, num_rows_s, num_cols_c, test_params);

        time.setTimePoint("online");
        if(rep == 0) {
            std::cout
                << "      Sent: " << chl.getTotalDataSent() << std::endl
                << "  received: " << chl.getTotalDataRecv() << std::endl << std::endl;
        }
        chl.resetStats();

        if(rep != 0)
            std::cout << time << std::endl;
    }


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

    std::vector<uv64> mat_s(num_rows_s, uv64(num_cols_s));
    std::vector<uv64> mat_s_t(num_cols_s, uv64(num_rows_s));
    for(ui32 row=0; row<num_rows_s; row++){
        mat_s[row] = get_dgg_testvector(num_cols_s, opt::p);
    }

    for(ui32 rep=0; rep<num_rep; rep++){
        Timer time;
        time.setTimePoint("start");

        ui32 rows_per_ct = test_params.phim/num_cols_c;
        uv32 index_list;
        for (ui32 i = 1; i < rows_per_ct; i++){
            index_list.push_back(test_params.phim-i*num_cols_c);
        }

        for(ui32 n=0; n<index_list.size(); n++){
            RelinKey rk(test_params.phim, num_windows);
            for(ui32 w=0; w<num_windows; w++){
                chl.recv(rk.a[w]);
                chl.recv(rk.b[w]);
            }
            g_rk_map[index_list[n]] =std::make_shared<RelinKey>(rk);
        }

        EncMat enc_mat_s;
        if(rows_per_ct > 1){
            enc_mat_s = preprocess_gemm_s(mat_s, num_cols_c, mat_window_size, mat_num_windows, test_params);
        }
        time.setTimePoint("setup");

        CTMat ct_mat_c(num_rows_c/rows_per_ct, std::vector<Ciphertext>(mat_num_windows, Ciphertext(opt::phim)));
        for(ui32 n=0; n<ct_mat_c.size(); n++){
            for(ui32 m=0; m<ct_mat_c[0].size(); m++){
                chl.recv(ct_mat_c[n][m].a);
                chl.recv(ct_mat_c[n][m].b);
            }
        }

        CTVec ct_prod;
        if(rows_per_ct > 1){
            ct_prod = gemm_online(ct_mat_c, enc_mat_s, num_cols_c, test_params);
        } else {
            ct_prod = gemm_phim_online(ct_mat_c, mat_s_t, mat_window_size, mat_num_windows, test_params);
        }

        for(ui32 n=0; n<ct_prod.size(); n++){
            chl.send(ct_prod[n].a);
            chl.send(ct_prod[n].b);
        }
        time.setTimePoint("online");

        if(rep != 0)
            std::cout << time << std::endl;
    }
    // std::cout << input_bits << std::endl;
    // std::cout << extractedMap << std::endl;

    chl.close();
    sess.stop();
    ios.stop();
    return;
}

int main(int argc, char** argv) {
    // std::cin >> n1_n3 >> n2;

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
