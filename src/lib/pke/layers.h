/*
 * layers.h
 *
 *  Created on: Aug 28, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_PKE_LAYERS_H_
#define SRC_LIB_PKE_LAYERS_H_

#include "utils/backend.h"
#include "pke/fv.h"
#include "pke_types.h"

namespace lbcrypto{

    typedef std::vector<Ciphertext> CTVec;
    typedef std::vector<std::vector<Ciphertext>> CTMat;

    typedef std::vector<std::vector<uv64>> EncMat;

    struct Filter2DShape{
        ui32 out_chn, in_chn, f_h, f_w;

        Filter2DShape(ui32 out_chn, ui32 in_chn, ui32 f_h, ui32 f_w) :
            out_chn(out_chn), in_chn(in_chn), f_h(f_h), f_w(f_w) {};
    };

    struct ConvShape{
        ui32 chn, h, w;

        ConvShape(ui32 chn, ui32 h, ui32 w) :
            chn(chn), h(h), w(w) {};
    };

    struct Filter2D{
        Filter2DShape shape;
        std::vector<std::vector<std::vector<uv64>>> w;
        uv64 b;

        Filter2D(ui32 out_chn, ui32 in_chn, ui32 f_h, ui32 f_w) :
            shape(out_chn, in_chn, f_h, f_w),
            w(out_chn, std::vector<std::vector<uv64>>(in_chn,  std::vector<uv64>(f_h, uv64(f_w)))),
            b(out_chn) {};
    };

    struct ConvLayer{
        ConvShape shape;
        std::vector<std::vector<uv64>> act;

        ConvLayer(ui32 chn, ui32 h, ui32 w) :
            shape(chn, h, w), act(chn, std::vector<uv64>(h,  uv64(w))) {};
    };

}



#endif /* SRC_LIB_PKE_LAYERS_H_ */
