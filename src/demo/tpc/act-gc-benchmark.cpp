/*
 This file is part of JustGarble.

    JustGarble is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    JustGarble is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <iostream>
#include <algorithm>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>

#include "pke/gazelle.h"
#include "gc/gc.h"
#include "gc/util.h"
#include "gc/gazelle_circuits.h"
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;
using namespace lbcrypto;

void buildCircuit(GarbledCircuit& gc, BuildContext& context,
        ui64 width, ui64 in_args, ui64 n_circ, ui64 p) {
    std::vector<uv64> in(in_args, uv64(width));
    uv64 out(width);
    uv64 s_p(width); 
    uv64 s_p_2(width);

    int n = n_circ*width*in_args;
    int m = n_circ*width;

    startBuilding(&gc, &context, n, m, n_circ*1000);
    gc.n_c = n_circ*width;
    CONSTCircuit(&gc, &context, p, width, s_p);
    CONSTCircuit(&gc, &context, p/2, width, s_p_2);
    for(ui64 i=0; i<n_circ; i++){
        for(ui64 j=0; j<in_args; j++){
            fill_vector(in[j], (j*n_circ+i)*width);
        }
        // ANDCircuit(&gc, &context, in[0], in[1], out);
        A2BCircuit(&gc, &context, s_p, in[0], in[1], out);
        // ui64 carry;
        // ADDCircuit(&gc, &context, in[0], in[1], out, carry);
        addOutputs(&gc, &context, out);
    }
    finishBuilding(&gc, &context);

    return;
}

void func_ref(uv64& din, uv64& dref, ui64 mask, ui64 p){
    // dref[0] = (din[0] & din[1]) & mask;
    dref[0] = (din[0] + din[1]) % p;
    // dref[0] = (din[0] + din[1]) & mask;
}

int main() {
    ui64 n_circ = 20;
    ui64 in_args = 9, out_args = 1;
    ui64 width = 22;
    ui64 p = 307201;

    std::vector<uv64> din = std::vector<uv64>(n_circ, uv64(in_args));
    std::vector<uv64> dref = std::vector<uv64>(n_circ, uv64(out_args));
    std::vector<uv64> dout_pt = std::vector<uv64>(n_circ, uv64(out_args));
    std::vector<uv64> dout = std::vector<uv64>(n_circ, uv64(out_args));

    for(ui32 n=0; n<n_circ; n++){
        ui64 mask = ((1 << width)-1);
        // din[n] = get_uniform_testvector(in_args, mask);
        din[n] = get_uniform_testvector(in_args, p-1);
        // func_ref(din[n], dref[n], mask, p);
        // relu_ref(din[n], dref[n], mask, p);
        pool2_ref(din[n], dref[n], mask, p);
    }

    GarbledCircuit gc;
    BuildContext context;
    // buildCircuit(gc, context, width, in_args, n_circ, p);
    // buildRELULayer(gc, context, width, n_circ, p);
    buildPool2Layer(gc, context, width, n_circ, p);
    BitVector inputBitMap(gc.n);
    BitVector outputBitMap(gc.m);

    // Pack plaintext into bits
    pack_inputs(din, inputBitMap, width);

    // Evaluate plaintext
    evaluate_pt(&gc, inputBitMap, outputBitMap);
    unpack_outputs(outputBitMap, dout_pt, width);

    // Garble the circuit
    InputLabels inputLabels(gc.n);
    OutputMap outputOTPBitMap(gc.m);
    garbleCircuit(&gc, inputLabels, outputOTPBitMap);

    // Print Circuit Info
    // print_gc(gc);

    // Extract the input labels
    ExtractedLabels extractedLabels(gc.n);
    extractLabels(extractedLabels, inputLabels, inputBitMap);
    // for (ui64 i=0; i<extractedLabels.size(); i++){
    //     print_block(extractedLabels[i]);
    //     printf("\n");
    // }

    // Evaluate garbled circuits
    OutputLabels eval_outputs(gc.m);
    evaluate(&gc, extractedLabels, eval_outputs);

    // std::cout << "Eval Outputs: " << std::endl;
    // for (ui64 i=0; i<eval_outputs.size(); i++){
    //     print_block(eval_outputs[i]);
    //     printf("\n");
    // }

    // Map the outputs to 
    BitVector extractedMap(gc.m);
    mapOutputs(outputOTPBitMap, eval_outputs, extractedMap);
    unpack_outputs(extractedMap, dout, width);

    print_results(din, dout_pt, dout, dref);

    return 0;
}

