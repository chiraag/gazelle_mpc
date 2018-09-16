#ifndef LBCRYPTO_MATH_PARAMS_H
#define LBCRYPTO_MATH_PARAMS_H

#include "utils/backend.h"
#include "math/bit_twiddle.h"

namespace lbcrypto {
    namespace opt {
        extern ui32 logn;
        extern ui32 phim;

        extern ui64 q;
        extern ui64 z;
        extern ui64 p;
        extern ui64 z_p;
        extern ui64 mu;
        extern ui64 mu_h;
        extern ui64 mu_l;
        // extern ui64 z;
        extern ui64 delta;
        extern ui64 delta16;
        extern ui64 q4;
        extern ui64 delta2;
        extern ui64 p2;

        inline ui64 modp_part(ui64 a){
            // The constant here is 2*ceil(log2(p))+2
            return (a - ((a*mu) >> 42)*p);
        }

        /*inline ui64 modp_part(ui64 a){
            return  (a - ((a*mu_h + ((a*mu_l) >> 4)) >> 40)*p);
        }*/

        inline ui64 modp_full(ui64 a){
            ui64 b = modp_part(a);
            return ((b >= p)? b-p: b);
        }

        inline ui64 modp_finalize(ui64 a){
            return ((a >= p)? a-p: a);
        }

        inline ui64 modq_part(ui128 a){
            ui128 b = (ui128)((ui64)a) + (a >> 64)*(ui128)delta16;  // (64b) + (60+34=94b) = max(95b)
            ui64 c = (ui64)(b >> 61)*delta2 + ((ui64)b & ones(61));  // max (34+31=65b) + (61b) = 62b
            return c;
        }

        inline ui64 modq_full(ui128 a){
            ui64 b = modq_part(a);
            while(b >= q){
                b -= q;
            }
            return b;
        }

        inline ui64 modq_part(ui64 a){
            return (a >> 60)*delta + (a & ones(60));
        }

        inline ui64 modq_full(ui64 a){
            ui64 b = modq_part(a);
            while(b >= q){
                b -= q;
            }
            return b;
        }

        inline ui64 sub_modq_part(ui64 a, ui64 b){
            return modq_part(a + q4 - b);
        }

        inline ui64 mul_modq_part(ui64 a, ui64 b){
            ui128 c = (ui128)a*(ui128)b; // 124b number
            return modq_part(c);
        }

        inline ui64 lshift_modq_part(ui64 a, ui32 shift){
            ui128 c = ((ui128)a << shift); // 124b number
            return modq_part(c);
        }
    }
}


#endif
