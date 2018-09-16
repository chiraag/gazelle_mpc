/*
 * conv2d.cpp
 *
 *  Created on: Sep 14, 2017
 *      Author: chiraag
 */

#include "math/bit_twiddle.h"
#include "math/automorph.h"
#include "pke/encoding.h"
#include "pke/fv.h"

#include "pke/conv2d.h"

#include "utils/test.h"
#include <iostream>
#include <algorithm>

namespace lbcrypto {

void update_ct_mat(CTMat& ct_mat, const ui32 ct_idx,
        const SecretKey& sk, const uv64& in,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    uv64 pt = packed_encode(in, params.p, params.logn);
    for(ui32 w=0; w<num_windows; w++){
        ct_mat[w][ct_idx] = Encrypt(sk, pt, params);

        // Scale for the next iteration
        for (ui32 i=0; i<params.phim; i++){
            pt[i] = ((pt[i] << window_size) % params.p);
        }
    }
}

CTMat preprocess_ifmap(const SecretKey& sk, const ConvLayer& in,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    ui32 chn_pow2 = nxt_pow2(in.shape.h*in.shape.w);
    ui32 row_pow2 = nxt_pow2(in.shape.w);

    if (row_pow2*2 > params.phim){
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else if(chn_pow2*2 > params.phim) {
        ui32 chn_pixels = row_pow2*in.shape.h;
        ui32 num_ct_chn = div_ceil(chn_pixels, params.phim);
        ui32 num_ct = num_ct_chn*2*div_ceil(in.shape.chn, 2);
        ui32 rows_per_ct = params.phim/2/row_pow2;

        CTMat ct_mat(num_windows, std::vector<Ciphertext>(num_ct, Ciphertext(params.phim)));
        for(ui32 curr_set=0; curr_set<div_ceil(in.shape.chn, 2); curr_set++){
            for(ui32 ct_offset=0; ct_offset<num_ct_chn*2; ct_offset++){
                // Pack the appropriate number of channels into a single ciphertext
                uv64 packed_rows(params.phim, 0);
                for(ui32 row_offset=0; row_offset<rows_per_ct; row_offset++){
                    ui32 curr_h = ct_offset+2*num_ct_chn*row_offset;
                    if(curr_h < in.shape.h){
                        for(ui32 curr_seg=0; curr_seg<2; curr_seg++){
                            ui32 dest = row_offset*row_pow2+curr_seg*(params.phim >> 1);
                            ui32 curr_chn = 2*curr_set + curr_seg;
                            // std::cout << "pre-process ifmap: " << ct_idx << " " << dest << " " << curr_chn << std::endl;

                            for(ui32 curr_w=0; curr_w<in.shape.w; curr_w++){
                                packed_rows[dest] = in.act[curr_chn][curr_h][curr_w];
                                dest++;
                            }
                        }
                    }
                }

                ui32 ct_idx = ct_offset + 2*num_ct_chn*curr_set;
                // Encode the packed channel and then encrypt its scaled copies
                update_ct_mat(ct_mat, ct_idx, sk, packed_rows, window_size, num_windows, params);
            }
        }

        return ct_mat;

    } else {
        // Pack multiple channels into a ciphertext

        ui32 tot_pixels = chn_pow2*in.shape.chn;
        ui32 num_ct = div_ceil(tot_pixels, params.phim);
        ui32 chn_per_ct = params.phim/chn_pow2;

        CTMat ct_mat(num_windows, std::vector<Ciphertext>(num_ct, Ciphertext(params.phim)));
        for(ui32 ct_idx=0; ct_idx<num_ct; ct_idx++){
            // Pack the appropriate number of channels into a single ciphertext
            uv64 packed_chn(params.phim, 0);
            for(ui32 chn_offset=0; chn_offset<chn_per_ct; chn_offset++){
                ui32 curr_chn = ct_idx*chn_per_ct+chn_offset;
                if(curr_chn == in.shape.chn) {
                    break;
                }

                ui32 dest = chn_offset*chn_pow2;
                // std::cout << "pre-process ifmap: " << ct_idx << " " << dest << " " << curr_chn << std::endl;

                for(ui32 curr_h=0; curr_h<in.shape.h; curr_h++){
                    for(ui32 curr_w=0; curr_w<in.shape.w; curr_w++){
                        packed_chn[dest] = in.act[curr_chn][curr_h][curr_w];
                        dest++;
                    }
                }
            }

            // Encode the packed channel and then encrypt its scaled copies
            update_ct_mat(ct_mat, ct_idx, sk, packed_chn, window_size, num_windows, params);
        }

        return ct_mat;
    }
}

EncMat preprocess_filter(const Filter2D& filter, const ConvShape& shape,
         const ui32 window_size, const ui32 num_windows, const FVParams& params){
    ui32 chn_pow2 = nxt_pow2(shape.h*shape.w);
    ui32 row_pow2 = nxt_pow2(shape.w);

    ui32 offset_h = (filter.shape.f_h-1)/2;
    ui32 offset_w = (filter.shape.f_w-1)/2;

    if (row_pow2*2 > params.phim){
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else if(chn_pow2*2 > params.phim) {
        throw std::logic_error("Channels larger than half a ciphertext not supported");
    } else {
        ui32 chn_per_ct = params.phim/chn_pow2;
        ui32 chn_per_seg = chn_per_ct/2;

        ui32 in_ct = div_ceil(filter.shape.in_chn, chn_per_ct);
        ui32 out_ct = div_ceil(filter.shape.out_chn, chn_per_ct);
        ui32 inner_loop = chn_per_ct;
        ui32 rot_per_in = inner_loop*filter.shape.f_h*filter.shape.f_w;
        
        // Create the diagonal rotation of the plaintext matrix
        ui32 enc_row = 0;
        ui32 num_filter_rows = in_ct*rot_per_in*out_ct;
        EncMat enc_filter(num_filter_rows, std::vector<uv64>(num_windows, uv64(params.phim)));

        for(ui32 in_chn_base=0; in_chn_base<filter.shape.in_chn; in_chn_base+=chn_per_ct){
            for(ui32 curr_loop=0; curr_loop<inner_loop; curr_loop++){
                for(ui32 f_h=0; f_h<filter.shape.f_h; f_h++){
                    for(ui32 f_w=0; f_w<filter.shape.f_w; f_w++){
                        for(ui32 out_chn_base=0; out_chn_base<filter.shape.out_chn; out_chn_base+=chn_per_ct){
                            // Create a vector with filter_coeff and zeros
                            uv64 filter_base(params.phim, 0);
                            for(ui32 curr_offset=0; curr_offset<chn_per_ct; curr_offset++){
                                ui32 delta_out = (curr_offset % chn_per_ct);
                                ui32 delta_in = ((curr_offset+curr_loop) % chn_per_seg +
                                    (curr_loop/chn_per_seg)*chn_per_seg +
                                    (curr_offset/chn_per_seg)*chn_per_seg) % chn_per_ct;

                                ui32 curr_in = in_chn_base + delta_in;
                                ui32 curr_out = out_chn_base + delta_out;

                                //std::cout << "curr_in: " << curr_in << " curr_out: " << curr_out << std::endl;
                                ui64 coeff = ((curr_in >= filter.shape.in_chn) || (curr_out >= filter.shape.out_chn))? 0:
                                        filter.w[curr_out][curr_in][f_h][f_w];

                                ui32 dest = curr_offset*chn_pow2;
                                /*if(coeff != 0){
                                    std::cout << "coeff: " << coeff << " dest: " << dest << std::endl;
                                }*/
                                for(ui32 curr_h=0; curr_h<shape.h; curr_h++){
                                    for(ui32 curr_w=0; curr_w<shape.w; curr_w++){
                                        bool zero = ((curr_w+f_w) < offset_w) ||
                                                ((curr_w+f_w) >= (offset_w+shape.w)) ||
                                                ((curr_h+f_h) < offset_h) ||
                                                ((curr_h+f_h) >= (offset_h+shape.h));
                                        filter_base[dest] = zero? 0: coeff;
                                        dest++;
                                    }
                                }
                            }

                            // std::cout << enc_row << ": " <<  vec_to_str(filter_base) << std::endl;

                            // Encode to coeff, decompose into windows and encode to eval
                            auto pt_row = packed_encode(filter_base, params.p, params.logn);
                            auto decomposed_row = base_decompose(pt_row, window_size, num_windows);
                            for(ui32 w=0; w<num_windows; w++){
                                enc_filter[enc_row][w] = NullEncrypt(decomposed_row[w], params);
                            }
                            enc_row++;
                        }
                    }
                }
            }
        }


        return enc_filter;
    }
}

CTVec conv_2d_online(const CTMat& ct_mat, const EncMat& enc_mat,
        const Filter2DShape& filter_shape, const ConvShape& in_shape, const FVParams& params){
    ui32 chn_pow2 = nxt_pow2(in_shape.h*in_shape.w);
    ui32 row_pow2 = nxt_pow2(in_shape.w);

    ui32 offset_h = (filter_shape.f_h-1)/2;
    ui32 offset_w = (filter_shape.f_w-1)/2;

    if (row_pow2*2 > params.phim){
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else if(chn_pow2*2 > params.phim) {
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else {
        ui32 chn_per_ct = params.phim/chn_pow2;
        ui32 in_ct = div_ceil(filter_shape.in_chn, chn_per_ct);
        ui32 out_ct = div_ceil(filter_shape.out_chn, chn_per_ct);
        ui32 inner_loop = chn_per_ct;

        CTVec ct_vec(out_ct, Ciphertext(params.phim));
        Ciphertext rot_vec(params.phim);

        // Input stationary computation over all the plaintext windows
        for(ui32 w=0; w<ct_mat.size(); w++){
            ui32 row = 0;
            for(ui32 curr_in_ct=0; curr_in_ct<in_ct; curr_in_ct++){
                auto digits_vec_w = HoistedDecompose(ct_mat[w][curr_in_ct], params);

                // Compute the rotation index
                for(ui32 curr_loop=0; curr_loop<inner_loop; curr_loop++){
                    ui32 rot_base = curr_loop*chn_pow2;
                    for(ui32 f_h=0; f_h<filter_shape.f_h; f_h++){
                        ui32 rot_h = (f_h-offset_h)*in_shape.w;
                        for(ui32 f_w=0; f_w<filter_shape.f_w; f_w++){
                            ui32 rot_w = (f_w-offset_w);
                            ui32 rot_f = ((rot_base + rot_h + rot_w) & ((params.phim >> 1) - 1));
                            ui32 rot = (rot_base & (params.phim >> 1)) + rot_f;

                            // Rotate if necessary
                            const Ciphertext *curr_vec = &ct_mat[w][curr_in_ct];
                            if(rot != 0){
                                auto rk = GetAutomorphismKey(rot);
                                rot_vec = EvalAutomorphismDigits(rot, *rk, *curr_vec, digits_vec_w, params);
                                curr_vec = &rot_vec;
                            }

                            // Accumulate to all the outputs
                            for(ui32 curr_out_ct=0; curr_out_ct<out_ct; curr_out_ct++){
                                auto mult = EvalMultPlain(*curr_vec, enc_mat[row][w], params);
                                ct_vec[curr_out_ct] = EvalAdd(ct_vec[curr_out_ct], mult, params);
                                // std::cout << w << " " << curr_in_ct << " " << row << " " << rot << std::endl;
                                row++;
                            }
                        }
                    }
                }
            }
        }

        return ct_vec;
    }
}

EncMat preprocess_filter_2stage(const Filter2D& filter, const ConvShape& shape,
         const ui32 window_size, const ui32 num_windows, const FVParams& params){
    ui32 chn_pow2 = nxt_pow2(shape.h*shape.w);
    ui32 row_pow2 = nxt_pow2(shape.w);

    ui32 offset_h = (filter.shape.f_h-1)/2;
    ui32 offset_w = (filter.shape.f_w-1)/2;

    if (row_pow2*2 > params.phim){
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else if(chn_pow2*2 > params.phim) {
        ui32 chn_pixels = row_pow2*shape.h;
        ui32 num_ct_chn = div_ceil(chn_pixels, params.phim);

        if(num_ct_chn < offset_h){
            throw std::logic_error("Unsupported filter and input combination");
        }

        ui32 rows_per_ct = params.phim/2/row_pow2;
        ui32 in_ct = num_ct_chn*2*div_ceil(filter.shape.in_chn, 2);
        ui32 rot_per_in = filter.shape.f_h*filter.shape.f_w;
        ui32 out_ct = 2*div_ceil(filter.shape.out_chn, 2);

        // Create the diagonal rotation of the plaintext matrix
        ui32 enc_row = 0;
        ui32 num_filter_rows = in_ct*rot_per_in*out_ct;
        EncMat enc_filter(num_filter_rows, std::vector<uv64>(num_windows, uv64(params.phim)));
        // std::cout << "Number of filters: " << num_filter_rows << std::endl;

        for(ui32 in_set=0; in_set<div_ceil(filter.shape.in_chn, 2); in_set++){
            for(ui32 in_row_idx=0; in_row_idx<2*num_ct_chn; in_row_idx++){
                for(ui32 f_w=0; f_w<filter.shape.f_w; f_w++){
                    for(ui32 f_h=0; f_h<filter.shape.f_h; f_h++){
                        for(ui32 out_set=0; out_set<div_ceil(filter.shape.out_chn, 2); out_set++){
                            bool first_skip = (in_row_idx+offset_h < f_h);
                            bool last_skip = (in_row_idx+offset_h >= (2*num_ct_chn+f_h));

                            for(ui32 curr_loop=0; curr_loop<2; curr_loop++){
                                // Create a vector with filter_coeff and zeros
                                uv64 filter_base(params.phim, 0);
                                for(ui32 curr_offset=0; curr_offset<2; curr_offset++){
                                    ui32 curr_in = 2*in_set + curr_offset;
                                    ui32 curr_out = 2*out_set + (curr_offset+curr_loop)%2;

                                    ui64 coeff = ((curr_in >= filter.shape.in_chn) || (curr_out >= filter.shape.out_chn))? 0:
                                            filter.w[curr_out][curr_in][f_h][f_w];
                                    /* std::cout << "curr_in: " << curr_in
                                            << " curr_out: " << curr_out
                                            << " coeff: " << coeff << std::endl; */

                                    ui32 dest = curr_offset*params.phim/2;
                                    /*if(coeff != 0){
                                        std::cout << "coeff: " << coeff << " dest: " << dest << std::endl;
                                    }*/
                                    for(ui32 curr_h=0; curr_h<rows_per_ct; curr_h++){
                                        for(ui32 curr_w=0; curr_w<shape.w; curr_w++){
                                            bool zero = (((curr_h == 0) && last_skip) ||
                                                    ((curr_h == rows_per_ct-1) && first_skip) ||
                                                    ((curr_w+f_w) < offset_w) ||
                                                    ((curr_w+f_w) >= (offset_w+shape.w)));
                                            filter_base[dest] = zero? 0: coeff;
                                            dest++;
                                        }
                                    }
                                }

                                // std::cout << first_skip << " " << last_skip << std::endl;
                                // std::cout << enc_row << ": " <<  vec_to_str(filter_base) << std::endl;
                                // std::cout << std::endl;

                                // Encode to coeff, decompose into windows and encode to eval
                                auto pt_row = packed_encode(filter_base, params.p, params.logn);
                                auto decomposed_row = base_decompose(pt_row, window_size, num_windows);
                                for(ui32 w=0; w<num_windows; w++){
                                    enc_filter[enc_row][w] = NullEncrypt(decomposed_row[w], params);
                                }
                                enc_row++;
                            }
                        }
                    }
                }
            }
        }

        return enc_filter;
    } else {
        ui32 chn_per_ct = params.phim/chn_pow2;
        ui32 chn_per_seg = chn_per_ct/2;

        ui32 in_ct = div_ceil(filter.shape.in_chn, chn_per_ct);
        ui32 out_ct = div_ceil(filter.shape.out_chn, chn_per_ct);
        ui32 inner_loop = chn_per_ct;
        ui32 rot_per_in = inner_loop*filter.shape.f_h*filter.shape.f_w;

        // Create the diagonal rotation of the plaintext matrix
        ui32 enc_row = 0;
        ui32 num_filter_rows = in_ct*rot_per_in*out_ct;
        EncMat enc_filter(num_filter_rows, std::vector<uv64>(num_windows, uv64(params.phim)));

        for(ui32 in_chn_base=0; in_chn_base<filter.shape.in_chn; in_chn_base+=chn_per_ct){
            for(ui32 f_h=0; f_h<filter.shape.f_h; f_h++){
                for(ui32 f_w=0; f_w<filter.shape.f_w; f_w++){
                    for(ui32 out_chn_base=0; out_chn_base<filter.shape.out_chn; out_chn_base+=chn_per_ct){
                        for(ui32 curr_loop=0; curr_loop<inner_loop; curr_loop++){
                            // Create a vector with filter_coeff and zeros
                            uv64 filter_base(params.phim, 0);
                            for(ui32 curr_offset=0; curr_offset<chn_per_ct; curr_offset++){
                                ui32 delta_in = (curr_offset % chn_per_ct);
                                ui32 delta_out = ((curr_offset+curr_loop) % chn_per_seg +
                                    (curr_loop/chn_per_seg)*chn_per_seg +
                                    (curr_offset/chn_per_seg)*chn_per_seg) % chn_per_ct;

                                ui32 curr_in = in_chn_base + delta_in;
                                ui32 curr_out = out_chn_base + delta_out;

                                ui64 coeff = ((curr_in >= filter.shape.in_chn) || (curr_out >= filter.shape.out_chn))? 0:
                                        filter.w[curr_out][curr_in][f_h][f_w];
                                /* std::cout << "curr_in: " << curr_in
                                        << " curr_out: " << curr_out
                                        << " coeff: " << coeff << std::endl; */

                                ui32 dest = curr_offset*chn_pow2;
                                /*if(coeff != 0){
                                    std::cout << "coeff: " << coeff << " dest: " << dest << std::endl;
                                }*/
                                for(ui32 curr_h=0; curr_h<shape.h; curr_h++){
                                    for(ui32 curr_w=0; curr_w<shape.w; curr_w++){
                                        bool zero = ((curr_w+f_w) < offset_w) ||
                                                ((curr_w+f_w) >= (offset_w+shape.w)) ||
                                                ((curr_h+f_h) < offset_h) ||
                                                ((curr_h+f_h) >= (offset_h+shape.h));
                                        filter_base[dest] = zero? 0: coeff;
                                        dest++;
                                    }
                                }
                            }

                            // std::cout << enc_row << ": " <<  vec_to_str(filter_base) << std::endl;
                            // std::cout << std::endl;


                            // Encode to coeff, decompose into windows and encode to eval
                            auto pt_row = packed_encode(filter_base, params.p, params.logn);
                            auto decomposed_row = base_decompose(pt_row, window_size, num_windows);
                            for(ui32 w=0; w<num_windows; w++){
                                enc_filter[enc_row][w] = NullEncrypt(decomposed_row[w], params);
                            }
                            enc_row++;
                        }
                    }
                }
            }
        }

        return enc_filter;
    }
}

CTVec conv_2d_2stage_online(const CTMat& ct_mat, const EncMat& enc_mat,
        const Filter2DShape& filter_shape, const ConvShape& in_shape, const FVParams& params){
    ui32 chn_pow2 = nxt_pow2(in_shape.h*in_shape.w);
    ui32 row_pow2 = nxt_pow2(in_shape.w);

    ui32 offset_h = (filter_shape.f_h-1)/2;
    ui32 offset_w = (filter_shape.f_w-1)/2;

    if (row_pow2*2 > params.phim){
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else if(chn_pow2*2 > params.phim) {
        ui32 chn_pixels = row_pow2*in_shape.h;
        ui32 num_ct_chn = div_ceil(chn_pixels, params.phim);

        if(num_ct_chn < offset_h){
            throw std::logic_error("Unsupported filter and input combination");
        }

        // ui32 in_ct = num_ct_chn*2*div_ceil(filter_shape.in_chn, 2);
        ui32 out_ct = num_ct_chn*2*div_ceil(filter_shape.out_chn, 2);

        CTVec ct_mid(out_ct*2, Ciphertext(params.phim));
        CTVec rot_vec(2, Ciphertext(params.phim));

        // Input stationary computation over all the plaintext windows
        for(ui32 w=0; w<ct_mat.size(); w++){
            ui32 filter_row = 0;
            for(ui32 in_set=0; in_set<div_ceil(filter_shape.in_chn, 2); in_set++){
                for(ui32 in_row_idx=0; in_row_idx<2*num_ct_chn; in_row_idx++){
                    ui32 in_ct_idx = in_row_idx + in_set*2*num_ct_chn;

                    std::vector<uv64> digits_vec_w;
                    if((filter_shape.f_w > 1) || (in_row_idx < offset_h) ||
                            (in_row_idx >= (2*num_ct_chn-offset_h))) {
                        digits_vec_w = HoistedDecompose(ct_mat[w][in_ct_idx], params);
                    }

                    for(ui32 f_w=0; f_w<filter_shape.f_w; f_w++){
                        ui32 rot_w = (f_w-offset_w);
                        ui32 rot_h = 0;
                        if(in_row_idx < offset_h) {
                            rot_h = in_shape.w;
                        } else if (in_row_idx >= (2*num_ct_chn-offset_h)) {
                            rot_h = (params.phim >> 1)-in_shape.w;
                        }
                        ui32 rot_a = (rot_w & ((params.phim >> 1) - 1));
                        const Ciphertext *base_vec = &ct_mat[w][in_ct_idx];
                        if(rot_a != 0){
                            auto rk = GetAutomorphismKey(rot_a);
                            rot_vec[0] = EvalAutomorphismDigits(rot_a, *rk, *base_vec, digits_vec_w, params);
                            base_vec = &rot_vec[0];
                        }

                        ui32 rot_b = ((rot_h + rot_w) & ((params.phim >> 1) - 1));
                        const Ciphertext *alt_vec = &ct_mat[w][in_ct_idx];
                        if(rot_b != 0){
                            auto rk = GetAutomorphismKey(rot_b);
                            rot_vec[1] = EvalAutomorphismDigits(rot_b, *rk, *alt_vec, digits_vec_w, params);
                            alt_vec = &rot_vec[1];
                        }

                        for(ui32 f_h=0; f_h<filter_shape.f_h; f_h++){
                            ui32 out_row_idx = in_row_idx+offset_h;
                            // ui32 rot = 0;
                            const Ciphertext *curr_vec;
                            if(out_row_idx < f_h) {
                                out_row_idx += (2*num_ct_chn-f_h);
                                curr_vec = alt_vec;
                                // rot = rot_b;
                            } else if (out_row_idx >= (2*num_ct_chn+f_h)) {
                                out_row_idx -= (2*num_ct_chn+f_h);
                                curr_vec = alt_vec;
                                // rot = rot_b;
                            } else {
                                out_row_idx -= f_h;
                                curr_vec = base_vec;
                                // rot = rot_a;
                            }

                            // Accumulate to all the outputs
                            for(ui32 out_set=0; out_set<div_ceil(filter_shape.out_chn, 2); out_set++){
                                ui32 out_ct_idx = out_row_idx + out_set*2*num_ct_chn;

                                for(ui32 inner_loop=0; inner_loop<2; inner_loop++){
                                    ui32 mid_ct_idx = 2*out_ct_idx + inner_loop;

                                    auto mult = EvalMultPlain(*curr_vec, enc_mat[filter_row][w], params);
                                    ct_mid[mid_ct_idx] = EvalAdd(ct_mid[mid_ct_idx], mult, params);
                                    /* std::cout << w << " " << in_ct_idx << " " << f_w << " " << f_h
                                            << " " << filter_row << " "
                                            << rot << " " << mid_ct_idx << std::endl; */
                                    filter_row++;
                                }
                            }
                        }
                    }
                }
            }
        }

        CTVec ct_vec(out_ct, Ciphertext(params.phim));
        // Compute the rotation index
        for(ui32 curr_out_ct=0; curr_out_ct<out_ct; curr_out_ct++){
            // std::cout << curr_loop << " " << rot << std::endl;
            auto rot_vec = EvalAutomorphism(params.phim/2, ct_mid[curr_out_ct*2+1], params);
            ct_vec[curr_out_ct] = EvalAdd(ct_mid[curr_out_ct*2], rot_vec, params);
        }

        return ct_vec;
    } else {
        ui32 chn_per_ct = params.phim/chn_pow2;
        ui32 in_ct = div_ceil(filter_shape.in_chn, chn_per_ct);
        ui32 out_ct = div_ceil(filter_shape.out_chn, chn_per_ct);
        ui32 inner_loop = chn_per_ct;

        CTVec ct_mid(out_ct*inner_loop, Ciphertext(params.phim));
        Ciphertext rot_vec(params.phim);

        // Input stationary computation over all the plaintext windows
        for(ui32 w=0; w<ct_mat.size(); w++){
            ui32 row = 0;
            for(ui32 curr_in_ct=0; curr_in_ct<in_ct; curr_in_ct++){
                std::vector<uv64> digits_vec_w;
                if(filter_shape.f_h*filter_shape.f_w > 1) {
                    digits_vec_w = HoistedDecompose(ct_mat[w][curr_in_ct], params);
                }

                for(ui32 f_h=0; f_h<filter_shape.f_h; f_h++){
                    ui32 rot_h = (f_h-offset_h)*in_shape.w;
                    for(ui32 f_w=0; f_w<filter_shape.f_w; f_w++){
                        ui32 rot_w = (f_w-offset_w);
                        ui32 rot = ((rot_h + rot_w) & ((params.phim >> 1) - 1));

                        // Rotate if necessary
                        const Ciphertext *curr_vec = &ct_mat[w][curr_in_ct];
                        if(rot != 0){
                            auto rk = GetAutomorphismKey(rot);
                            rot_vec = EvalAutomorphismDigits(rot, *rk, *curr_vec, digits_vec_w, params);
                            curr_vec = &rot_vec;
                        }

                        // Accumulate to all the outputs
                        for(ui32 curr_out_ct=0; curr_out_ct<out_ct*inner_loop; curr_out_ct++){
                            auto mult = EvalMultPlain(*curr_vec, enc_mat[row][w], params);
                            ct_mid[curr_out_ct] = EvalAdd(ct_mid[curr_out_ct], mult, params);
                            // std::cout << w << " " << curr_in_ct << " " << row << " " << rot << std::endl;
                            row++;
                        }
                    }
                }
            }
        }

        CTVec ct_vec(out_ct, Ciphertext(params.phim));
        // Compute the rotation index
        for(ui32 curr_out_ct=0; curr_out_ct<out_ct; curr_out_ct++){
            ui32 base_idx = curr_out_ct*inner_loop;
            ct_vec[curr_out_ct] = ct_mid[base_idx];
            for(ui32 curr_loop=1; curr_loop<inner_loop; curr_loop++){
                ui32 rot_base = curr_loop*chn_pow2;
                ui32 rot_r = ((params.phim >> 1) - rot_base) & ((params.phim >> 1) - 1);
                ui32 rot = (rot_base & (params.phim >> 1)) + rot_r;

                // std::cout << curr_loop << " " << rot << std::endl;
                auto rot_vec = EvalAutomorphism(rot, ct_mid[base_idx+curr_loop], params);

                ct_vec[curr_out_ct] = EvalAdd(ct_vec[curr_out_ct], rot_vec, params);
            }
        }

        return ct_vec;
    }
}

ConvLayer postprocess_conv(const SecretKey& sk, const CTVec& ct_vec,
         const ConvShape& shape, const FVParams& params){
    ui32 chn_pow2 = nxt_pow2(shape.h*shape.w);
    ui32 row_pow2 = nxt_pow2(shape.w);

    if (row_pow2*2 > params.phim){
        throw std::logic_error("Rows larger than half a ciphertext not supported");
    } else if(chn_pow2*2 > params.phim) {
        ui32 chn_pixels = row_pow2*shape.h;
        ui32 num_ct_chn = div_ceil(chn_pixels, params.phim);
        ui32 rows_per_ct = params.phim/2/row_pow2;

        ConvLayer ofmap(shape.chn, shape.h, shape.w);
        for(ui32 out_set=0; out_set<div_ceil(shape.chn, 2); out_set++){
            for(ui32 out_row_idx = 0; out_row_idx < 2*num_ct_chn; out_row_idx++){
                ui32 curr_out_ct = out_row_idx + out_set*2*num_ct_chn;
                auto pt = packed_decode(Decrypt(sk, ct_vec[curr_out_ct], params), params.p, params.logn);

                // std::cout << vec_to_str(pt) << std::endl;
                ui32 src = 0;
                for(ui32 curr_seg=0; curr_seg<2; curr_seg++){
                    ui32 curr_chn = out_set*2 + curr_seg;

                    // std::cout << "post-proc ofmap: " << curr_chn << " " << src << std::endl;
                    for(ui32 h_offset=0; h_offset<rows_per_ct; h_offset++){
                        ui32 h = out_row_idx+2*num_ct_chn*h_offset;
                        for(ui32 w=0; w<shape.w; w++){
                            ofmap.act[curr_chn][h][w] = pt[src];
                            ofmap.act[curr_chn][h][w] = pt[src];
                            src++;
                        }
                    }
                    curr_chn++;
                    if(curr_chn == shape.chn){
                        break;
                    }
                }
            }
        } // when break is triggered we are already on the last ct

        return ofmap;
    } else {
        ui32 curr_chn = 0;
        ConvLayer ofmap(shape.chn, shape.h, shape.w);
        for(ui32 curr_out_ct = 0; curr_out_ct < ct_vec.size(); curr_out_ct++){
            auto pt = packed_decode(Decrypt(sk, ct_vec[curr_out_ct], params), params.p, params.logn);
            // std::cout << vec_to_str(pt) << std::endl;
            for(ui32 src_base=0; src_base<params.phim; src_base+=chn_pow2){
                ui32 src = src_base;
                //std::cout << "post-proc ofmap: " << curr_chn << " " << src_base << std::endl;
                for(ui32 h=0; h<shape.h; h++){
                    for(ui32 w=0; w<shape.w; w++){
                        ofmap.act[curr_chn][h][w] = pt[src];
                        src++;
                    }
                }
                curr_chn++;
                if(curr_chn == shape.chn){
                    break;
                }
            }
        } // when break is triggered we are already on the last ct

        return ofmap;
    }
}

ConvLayer conv_2d_pt(const ConvLayer& in, const Filter2D& filter, bool same, const ui32 p){
    ui32 out_h = in.shape.h - ((same) ? 0 : (filter.shape.f_h - 1));
    ui32 out_w = in.shape.w - ((same) ? 0 : (filter.shape.f_w - 1));

    ui32 offset_h = (same) ? (filter.shape.f_h-1)/2 : 0;
    ui32 offset_w = (same) ? (filter.shape.f_w-1)/2 : 0;

    ConvLayer out(filter.shape.out_chn, in.shape.h, in.shape.w);
    for(ui32 n=0; n<filter.shape.out_chn; n++){
        for (ui32 h = 0; h < out_h; h++){
            for (ui32 w = 0; w < out_w; w++){
                out.act[n][h][w] = filter.b[n];
                for(ui32 m=0; m<filter.shape.in_chn; m++){
                    for (ui32 f_h = 0; f_h < filter.shape.f_h; f_h++){
                        for (ui32 f_w = 0; f_w < filter.shape.f_w; f_w++){
                            ui32 in_h = h+f_h-offset_h;
                            ui32 in_w = w+f_w-offset_w;
                            // Uses the wrap-around property of ui32 to discard negative
                            bool zero = (same && (in_h >= in.shape.h || in_w >= in.shape.w));
                            ui64 in_act = zero ? 0:in.act[m][in_h][in_w];
                            out.act[n][h][w] += (filter.w[n][m][f_h][f_w]*in_act);
                        }
                    }
                }
                out.act[n][h][w] = out.act[n][h][w] % p;
            }
        }
    }

    return out;
}

bool check_conv(const ConvLayer& ofmap, const ConvLayer& ofmap_ref){
    if((ofmap.shape.chn != ofmap_ref.shape.chn) ||
            (ofmap.shape.h != ofmap_ref.shape.h) ||
            (ofmap.shape.w != ofmap_ref.shape.w)){
        return false;
    } else {
        for(ui32 chn=0; chn<ofmap.shape.chn; chn++){
            for (ui32 h = 0; h < ofmap.shape.h; h++){
                for (ui32 w = 0; w < ofmap.shape.w; w++){
                    if(ofmap.act[chn][h][w] != ofmap_ref.act[chn][h][w]){
                        return false;
                    }
                }
            }
            // std::cout << "channel " << chn << " matched" << std::endl;
        }

        return true;
    }
}

}
