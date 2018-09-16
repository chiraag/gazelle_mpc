/*
 * test.cpp
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#include <utils/backend.h>
#include "utils/test.h"

namespace lbcrypto {

sv64 to_signed(uv64 v, ui64 p){
    sv64 sv(v.size());
    ui64 bound = p >> 1;
    for(ui32 i=0; i<v.size(); i++){
        sv[i] = (v[i] > bound) ? -1*(si64)(p-v[i]): v[i];
    }

    return sv;
}

}
