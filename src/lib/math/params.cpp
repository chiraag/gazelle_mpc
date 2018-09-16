/*
 * params.cpp
 *
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 */

#include <utils/backend.h>
#include "math/params.h"

namespace lbcrypto {
    namespace opt {
        ui32 logn = 11;
        ui32 phim = (1 << logn);

        /*
        //q (<60 bits), p (>18) bits
        ui64 q(1152921504346550273);
        ui64 z(236170385413442746);
        ui64 p(307201);
        ui64 z_p(227254);
        ui64 mu = ((ui64)1 << (2*19+2))/p; //  [Adjusted for fast partial]
        */


        //q (<60 bits), p (>19) bits
        ui64 q(1152921504499937281);
        ui64 z(246029739010950493);
        ui64 p(557057);
        ui64 z_p(201127);
        ui64 mu = ((ui64)1 << (2*20+2))/p; //  [Adjusted for fast partial]


        /* //q (<60 bits), p (>20) bits
        ui64 q(1152921504414760961);
        ui64 z(1012134726195831682);
        ui64 p(1712129);
        ui64 z_p(290337);
        ui64 mu = ((ui64)1 << (2*21+2))/p; //  [Adjusted for fast partial]
        ui64 mu_h = (mu >> 4); //  [Adjusted for fast partial]
        ui64 mu_l = (mu % 16); //  [Adjusted for fast partial]
        */


        // ui64 z(824956925455712260);
        ui64 delta = ((ui64)1<<60)-q;
        ui64 delta16 = delta << 4;
        ui64 q4 = q << 2;
        ui64 delta2 = delta << 1;

        ui64 p2 = (p << 1);
    }
}
