/*
NN-Layers-Benchmarking: This code benchmarks FC and Conv layers for a neural network

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <utils/backend.h>
#include <iostream>
#include <random>
#include "pke/gazelle.h"

using namespace std;
using namespace lbcrypto;

int main() {
    std::cout << "Conv2D Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep = 1;
    double start, stop;

    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);
    precompute_automorph_index(opt::phim);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams slow_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        8
    };

    FVParams fast_params = slow_params;
    fast_params.fast_modulli = true;

    FVParams test_params = fast_params;

    //------------------- Synthetic Data -------------------
    ui32 out_chn = 5, in_chn = 1, in_h = 28, in_w = 28;
    ui32 f_h = 5, f_w = 5;
    ui32 w_sz = 9;
    ui32 conv_type = 0;
    // std::cin >> out_chn >> in_chn >> in_h >> in_w >> f_w >> f_h >> w_sz >> conv_type;
    test_params.window_size = w_sz;

    ConvLayer ifmap(in_chn, in_h, in_w);
    for(ui32 chn=0; chn<in_chn; chn++){
        for(ui32 h=0; h<in_h; h++){
            ifmap.act[chn][h] = get_dgg_testvector(in_w, opt::p);
            // std::cout << vec_to_str(ifmap.act[chn][h]) << std::endl;
            /*ifmap.act[chn][h] = uv64(in_w);
            for(ui32 w=0; w<in_w; w++){
                ifmap.act[chn][h][w] = 100*h+w+1;
                // std::cout << vec_to_str(ifmap.act[chn][h]) << std::endl;
            }*/
        }
    }

    Filter2D filter(out_chn, in_chn, f_h, f_w);
    for(ui32 ochn=0; ochn<out_chn; ochn++){
        for(ui32 ichn=0; ichn<in_chn; ichn++){
            // std::cout << ochn << " " << ichn << std::endl;
            for(ui32 h=0; h<f_h; h++){
                filter.w[ochn][ichn][h] = get_dgg_testvector(f_w, opt::p);
                // filter.w[ochn][ichn][h] = uv64(f_w);
                // std::cout << vec_to_str(filter.w[ochn][ichn][h]) << std::endl;
            }
            // std::cout << std::endl;
        }
    }
    // filter.w[0][0][0][0] = 1;

    auto ofmap_ref = conv_2d_pt(ifmap, filter, true, opt::p);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ofmap_ref = conv_2d_pt(ifmap, filter, true, opt::p);
    }
    stop = currentDateTime();
    std::cout << " Plaintext: " << (stop-start)/nRep << std::endl;
    /*for(ui32 chn=0; chn<out_chn; chn++){
        for(ui32 h=0; h<in_h; h++){
            std::cout << vec_to_str(ofmap_ref.act[chn][h]) << std::endl;
        }
    }*/

    //----------------------- KeyGen -----------------------
    nRep = 1;
    auto kp = KeyGen(test_params);

    ui32 chn_pow2 = nxt_pow2(ifmap.shape.h*ifmap.shape.w);
    ui32 offset_h = (filter.shape.f_h-1)/2;
    ui32 offset_w = (filter.shape.f_w-1)/2;

    ui32 chn_per_ct = opt::phim/chn_pow2;
    ui32 inner_loop = chn_per_ct;

    uv32 index_list;
    if(conv_type == 0){
        for(ui32 curr_loop=0; curr_loop<inner_loop; curr_loop++){
            ui32 rot_base = curr_loop*chn_pow2;
            for(ui32 f_y=0; f_y<filter.shape.f_h; f_y++){
                ui32 rot_h = (f_y-offset_h)*ifmap.shape.w;
                for(ui32 f_x=0; f_x<filter.shape.f_w; f_x++){
                    ui32 rot_w = (f_x-offset_w);
                    ui32 rot_f = ((rot_base + rot_h + rot_w) & ((opt::phim >> 1) - 1));
                    ui32 rot = (rot_base & (opt::phim >> 1)) + rot_f;

                    index_list.push_back(rot);
                }
            }
        }
    } else {
        for(ui32 f_y=0; f_y<filter.shape.f_h; f_y++){
            ui32 rot_h = (f_y-offset_h)*ifmap.shape.w;
            for(ui32 f_x=0; f_x<filter.shape.f_w; f_x++){
                ui32 rot_w = (f_x-offset_w);
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
        index_list.push_back(opt::phim/2);
    }

    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        kp = KeyGen(test_params);
        EvalAutomorphismKeyGen(kp.sk, index_list, test_params);
    }
    stop = currentDateTime();
    std::cout << " KeyGen ("<< index_list.size() <<" keys): " << (stop-start)/nRep << std::endl;

    nRep = 1;
    ui32 pt_window_size = 10;
    ui32 pt_num_windows = 2;

    //----------------- Preprocess Filter ------------------
    auto enc_filter = (conv_type) ?
            preprocess_filter_2stage(filter, ifmap.shape, pt_window_size, pt_num_windows, test_params):
            preprocess_filter(filter, ifmap.shape, pt_window_size, pt_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        enc_filter = (conv_type) ?
                preprocess_filter_2stage(filter, ifmap.shape, pt_window_size, pt_num_windows, test_params):
                preprocess_filter(filter, ifmap.shape, pt_window_size, pt_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Filter: " << (stop-start)/nRep << std::endl;
    //std::cout << vec_to_str(enc_filter[0][0]) << std::endl;
    //std::cout << vec_to_str(enc_filter[0][1]) << std::endl;

    //----------------- Preprocess Vector ------------------
    auto ct_mat = preprocess_ifmap(kp.sk, ifmap, pt_window_size, pt_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_mat = preprocess_ifmap(kp.sk, ifmap, pt_window_size, pt_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Vector ("<< pt_num_windows <<" windows): " << (stop-start)/nRep << std::endl;

    //auto pt = packed_decode(Decrypt(kp.sk, ct_mat[0][0], test_params), opt::p, opt::logn);
    //std::cout << vec_to_str(pt) << std::endl;
    //pt = packed_decode(Decrypt(kp.sk, ct_mat[1][0], test_params), opt::p, opt::logn);
    //std::cout << vec_to_str(pt) << std::endl;


    //------------------------ Conv2D ----------------------
    auto ct_conv = (conv_type) ?
            conv_2d_2stage_online(ct_mat, enc_filter, filter.shape, ifmap.shape, test_params):
            conv_2d_online(ct_mat, enc_filter, filter.shape, ifmap.shape, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_conv = (conv_type) ?
                    conv_2d_2stage_online(ct_mat, enc_filter, filter.shape, ifmap.shape, test_params):
                    conv_2d_online(ct_mat, enc_filter, filter.shape, ifmap.shape, test_params);
    }
    stop = currentDateTime();
    std::cout << " Conv2D: " << (stop-start)/nRep << std::endl;


    //------------------- Post-Process ---------------------
    auto ofmap = postprocess_conv(kp.sk, ct_conv, ofmap_ref.shape, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ofmap = postprocess_conv(kp.sk, ct_conv, ofmap_ref.shape, test_params);
    }
    stop = currentDateTime();
    std::cout << " Post-Process: " << (stop-start)/nRep << std::endl;

    //----------------------- Check ------------------------
    std::cout << std::endl;
    std::cout << "Margin ct: " << NoiseMargin(kp.sk, ct_mat[0][0], test_params) << std::endl;
    double min_margin = 64.0;
    for(ui32 n=0; n<ct_conv.size(); n++){
        auto curr_margin = NoiseMargin(kp.sk, ct_conv[n], test_params);
        if(curr_margin < min_margin){
            min_margin = curr_margin;
        }
    }
    std::cout << "Margin conv: " << min_margin << std::endl;
    std::cout << std::endl;

    // std::cout << mat_to_str(ofmap.act[0]) << std::endl;
    // std::cout << mat_to_str(ofmap_ref.act[0]) << std::endl;
    auto eq = check_conv(ofmap, ofmap_ref);
    std::cout << "Check " << (eq?"succeeded":"failed") << std::endl;
    return 0;
}

