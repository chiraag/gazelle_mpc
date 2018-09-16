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
ui32 out_chn = 5, in_chn = 4, in_h = 14, in_w = 14;
ui32 f_h = 3, f_w = 3;
ui32 window_size = 9, conv_type = 0;
ui32 pt_window_size = 10, pt_num_windows = 2;
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

    Filter2DShape filter_shape(out_chn, in_chn, f_h, f_w);
    ConvShape output_shape(out_chn, in_h, in_w);
    ConvLayer ifmap(in_chn, in_h, in_w);

    ui32 chn_pow2 = nxt_pow2(ifmap.shape.h*ifmap.shape.w);
    ui32 offset_h = (filter_shape.f_h-1)/2;
    ui32 offset_w = (filter_shape.f_w-1)/2;

    ui32 chn_per_ct = opt::phim/chn_pow2;
    ui32 inner_loop = chn_per_ct;
    ui32 out_ct = div_ceil(filter_shape.out_chn, chn_per_ct);

    for(ui32 chn=0; chn<in_chn; chn++){
        for(ui32 h=0; h<in_h; h++){
            ifmap.act[chn][h] = get_dgg_testvector(in_w, opt::p);
            // std::cout << vec_to_str(ifmap.act[chn][h]) << std::endl;
        }
    }

    Timer time;
    chl.resetStats();
    time.setTimePoint("start");
    // KeyGen
    auto kp = KeyGen(test_params);

    uv32 index_list;
    if(conv_type == 0){
        for(ui32 curr_loop=0; curr_loop<inner_loop; curr_loop++){
            ui32 rot_base = curr_loop*chn_pow2;
            for(ui32 f_h=0; f_h<filter_shape.f_h; f_h++){
                ui32 rot_h = (f_h-offset_h)*ifmap.shape.w;
                for(ui32 f_w=0; f_w<filter_shape.f_w; f_w++){
                    ui32 rot_w = (f_w-offset_w);
                    ui32 rot_f = ((rot_base + rot_h + rot_w) & ((opt::phim >> 1) - 1));
                    ui32 rot = (rot_base & (opt::phim >> 1)) + rot_f;

                    index_list.push_back(rot);
                }
            }
        }
    } else {
        for(ui32 f_h=0; f_h<filter_shape.f_h; f_h++){
            ui32 rot_h = (f_h-offset_h)*ifmap.shape.w;
            for(ui32 f_w=0; f_w<filter_shape.f_w; f_w++){
                ui32 rot_w = (f_w-offset_w);
                ui32 rot = ((rot_h + rot_w) & ((opt::phim >> 1) - 1));

                index_list.push_back(rot);
            }
        }

        for(ui32 curr_loop=1; curr_loop<inner_loop; curr_loop++){
            ui32 rot_base = curr_loop*chn_pow2;
            ui32 rot_r = ((opt::phim >> 1) - rot_base) & ((opt::phim >> 1) - 1);
            ui32 rot = (rot_base & (opt::phim >> 1)) + rot_r;

            index_list.push_back(rot);
        }
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
        auto ct_mat = preprocess_ifmap(kp.sk, ifmap, pt_window_size, pt_num_windows, test_params);
        for(ui32 w=0; w<ct_mat.size(); w++){
            for(ui32 n=0; n<ct_mat[0].size(); n++){
                chl.send(ct_mat[w][n].a);
                chl.send(ct_mat[w][n].b);
            }
        }

        CTVec ct_conv(out_ct, Ciphertext(opt::phim));
        for(ui32 n=0; n<ct_conv.size(); n++){
            chl.recv(ct_conv[n].a);
            chl.recv(ct_conv[n].b);
        }
        auto ofmap = postprocess_conv(kp.sk, ct_conv, output_shape, test_params);
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

    ConvShape ifmap_shape(in_chn, in_h, in_w);
    Filter2D filter(out_chn, in_chn, f_h, f_w);

    ui32 chn_pow2 = nxt_pow2(ifmap_shape.h*ifmap_shape.w);
    ui32 offset_h = (filter.shape.f_h-1)/2;
    ui32 offset_w = (filter.shape.f_w-1)/2;

    ui32 chn_per_ct = opt::phim/chn_pow2;
    ui32 inner_loop = chn_per_ct;

    ui32 in_ct = div_ceil(filter.shape.in_chn, chn_per_ct);

    for(ui32 ochn=0; ochn<out_chn; ochn++){
        for(ui32 ichn=0; ichn<in_chn; ichn++){
            for(ui32 h=0; h<f_h; h++){
                filter.w[ochn][ichn][h] = get_dgg_testvector(f_w, opt::p);
                // std::cout << vec_to_str(filter.w[ochn][ichn][h]) << std::endl;
            }
        }
    }
    auto enc_filter = (conv_type) ?
            preprocess_filter_2stage(filter, ifmap_shape, pt_window_size, pt_num_windows, test_params):
            preprocess_filter(filter, ifmap_shape, pt_window_size, pt_num_windows, test_params);

    uv32 index_list;
    if(conv_type == 0){
        for(ui32 curr_loop=0; curr_loop<inner_loop; curr_loop++){
            ui32 rot_base = curr_loop*chn_pow2;
            for(ui32 f_h=0; f_h<filter.shape.f_h; f_h++){
                ui32 rot_h = (f_h-offset_h)*ifmap_shape.w;
                for(ui32 f_w=0; f_w<filter.shape.f_w; f_w++){
                    ui32 rot_w = (f_w-offset_w);
                    ui32 rot_f = ((rot_base + rot_h + rot_w) & ((opt::phim >> 1) - 1));
                    ui32 rot = (rot_base & (opt::phim >> 1)) + rot_f;

                    index_list.push_back(rot);
                }
            }
        }
    } else {
        for(ui32 f_h=0; f_h<filter.shape.f_h; f_h++){
            ui32 rot_h = (f_h-offset_h)*ifmap_shape.w;
            for(ui32 f_w=0; f_w<filter.shape.f_w; f_w++){
                ui32 rot_w = (f_w-offset_w);
                ui32 rot = ((rot_h + rot_w) & ((opt::phim >> 1) - 1));

                index_list.push_back(rot);
            }
        }

        for(ui32 curr_loop=1; curr_loop<inner_loop; curr_loop++){
            ui32 rot_base = curr_loop*chn_pow2;
            ui32 rot_r = ((opt::phim >> 1) - rot_base) & ((opt::phim >> 1) - 1);
            ui32 rot = (rot_base & (opt::phim >> 1)) + rot_r;

            index_list.push_back(rot);
        }
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
        CTMat ct_mat(pt_num_windows, std::vector<Ciphertext>(in_ct, Ciphertext(test_params.phim)));
        for(ui32 w=0; w<ct_mat.size(); w++){
            for(ui32 n=0; n<ct_mat[0].size(); n++){
                chl.recv(ct_mat[w][n].a);
                chl.recv(ct_mat[w][n].b);
            }
        }

        auto ct_conv = (conv_type) ?
                conv_2d_2stage_online(ct_mat, enc_filter, filter.shape, ifmap_shape, test_params):
                conv_2d_online(ct_mat, enc_filter, filter.shape, ifmap_shape, test_params);
        for(ui32 n=0; n<ct_conv.size(); n++){
            chl.send(ct_conv[n].a);
            chl.send(ct_conv[n].b);
        }
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
    std::cin >> out_chn >> in_chn >> in_h >> in_w >> f_w >> f_h >> window_size >> conv_type;

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
