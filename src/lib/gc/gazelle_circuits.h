/*
 * gazelle_circuits.h
 *
 *  Created on: Dec 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_GC_GAZELLE_CIRCUITS_H_
#define SRC_LIB_GC_GAZELLE_CIRCUITS_H_

#include "gc.h"
#include "gates.h"
#include "circuits.h"

namespace lbcrypto {

void A2BCircuit(GarbledCircuit *gc, BuildContext *context,
        const uv64& s_p, const uv64& s_c_x, const uv64& s_s_x, uv64& s_x);

void B2ACircuit(GarbledCircuit *gc, BuildContext *context,
        const uv64& s_p, const uv64& s_x, const uv64& s_s_x, uv64& s_c_x);

void ReLUCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& s_p,
        const uv64& s_p_2, const uv64& s_c_x, const uv64& s_s_x, const uv64& s_s_y, uv64& s_c_y);

void Pool2Circuit(GarbledCircuit *gc, BuildContext *context, const uv64& s_p,
        const uv64& s_p_2, const std::vector<uv64>& s_c_x,
        const std::vector<uv64>& s_s_x, const uv64& s_s_y, uv64& s_c_y);

ui64 fill_vector(uv64& v, ui64 start);

void buildRELULayer(GarbledCircuit& gc, BuildContext& context,
        ui64 width, ui64 n_circ, ui64 p);

void buildPool2Layer(GarbledCircuit& gc, BuildContext& context,
        ui64 width, ui64 n_circ, ui64 p);

void relu_ref(uv64& din, uv64& dref, ui64 mask, ui64 p);

void pool2_ref(uv64& din, uv64& dref, ui64 mask, ui64 p);

}

#endif /* SRC_LIB_GC_GAZELLE_CIRCUITS_H_ */
