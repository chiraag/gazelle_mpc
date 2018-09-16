/*
 * conv2d.h
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_PKE_CONV2D_H_
#define SRC_LIB_PKE_CONV2D_H_

#include "utils/backend.h"
#include "pke/layers.h"
#include "pke_types.h"

namespace lbcrypto {

    CTMat preprocess_ifmap(const SecretKey& sk, const ConvLayer& pt,
            const ui32 window_size, const ui32 num_windows, const FVParams& params);

    EncMat preprocess_filter(const Filter2D& filter, const ConvShape& shape,
             const ui32 window_size, const ui32 num_windows, const FVParams& params);

    CTVec conv_2d_online(const CTMat& ct_mat, const EncMat& enc_mat,
            const Filter2DShape& filter_shape, const ConvShape& in_shape, const FVParams& params);

    EncMat preprocess_filter_2stage(const Filter2D& filter, const ConvShape& shape,
             const ui32 window_size, const ui32 num_windows, const FVParams& params);

    CTVec conv_2d_2stage_online(const CTMat& ct_mat, const EncMat& enc_mat,
            const Filter2DShape& filter_shape, const ConvShape& in_shape, const FVParams& params);


    ConvLayer postprocess_conv(const SecretKey& sk, const CTVec& ct_vec,
             const ConvShape& shape, const FVParams& params);

    ConvLayer conv_2d_pt(const ConvLayer& in, const Filter2D& filter, bool same, const ui32 p);

    bool check_conv(const ConvLayer& ofmap, const ConvLayer& ofmap_ref);
}




#endif /* SRC_LIB_PKE_CONV2D_H_ */
