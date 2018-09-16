#include <utils/backend.h>
#include "automorph.h"
#include <map>

#include <iostream>

namespace lbcrypto {

    std::map<ui32, uv32> g_automorph_index;

    std::vector<uv64> base_decompose(const uv64& coeff, const ui32 window_size, const ui32 num_windows){
        ui32 phim = coeff.size();
        std::vector<uv64> decomposed(num_windows, uv64(phim));

        ui64 mask = (1 << window_size) - 1;
        for(ui32 j=0; j<phim; j++){
            ui64 curr_coeff = coeff[j];
            for(ui32 i=0; i<num_windows; i++){
                decomposed[i][j] = (curr_coeff & mask);
                curr_coeff = (curr_coeff >> window_size);
            }
        }

        return decomposed;
    }

    void precompute_automorph_index(const ui32 phim){
        uv32 automorph_indices = uv32(phim);

        ui32 g = 1;
        ui32 phim_by_2 = phim >> 1;
        ui32 mask = (phim << 1) - 1;
        for(ui32 i=0; i<phim/2; i++){
            automorph_indices[i] = g;
            automorph_indices[i+phim_by_2] = (g*mask) & mask;
            g = (g * 5) & mask;
        }
        g_automorph_index[phim] = std::move(automorph_indices);

        return;
    }

    ui32 get_automorph_index(const ui32 i, const ui32 phim){
        return g_automorph_index[phim][i];
    }

    uv64 automorph(const uv64& input, ui32 rot){
        ui32 phim = input.size();
        ui32 mask = phim-1;
        auto index = g_automorph_index[phim][rot];

        uv64 result(phim);
        auto idx = (index + 1)/2 - 1;
        for (ui32 j = 0; j < phim; j++) {
            //determines which power of primitive root unity we should switch to
            result[j] = input[idx];
            idx = (idx+index) & mask;
        }

        return result;
    }

    uv64 automorph_pt(const uv64& input, ui32 rot){
        ui32 phim = input.size();
        ui32 phim_by_2 = phim/2;
        ui32 inner_mask = (phim_by_2-1);
        ui32 inner_rot = rot & inner_mask;
        bool flip = ((rot & phim_by_2) != 0);

        uv64 result(phim);
        for(ui32 i=0; i<phim_by_2; i++){
            ui32 source = (i+inner_rot) & inner_mask;
            if(flip){
                result[i] = input[source+phim_by_2];
                result[i+phim_by_2] = input[source];
            } else {
                result[i] = input[source];
                result[i+phim_by_2] = input[source+phim_by_2];
            }
        }

        return result;
    }
}
