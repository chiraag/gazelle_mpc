/*
 * gazelle_circuits.cpp
 *
 *  Created on: Nov 30, 2017
 *      Author: chiraag
 */


#include "gazelle_circuits.h"

namespace lbcrypto {

void A2BCircuit(GarbledCircuit *gc, BuildContext *context,
        const uv64& s_p, const uv64& s_c_x, const uv64& s_s_x, uv64& s_x) {
    ui64 n = s_c_x.size();
    uv64 s_x_0, s_x_1;
    ui64 carry, nonneg;
    ADDCircuit(gc, context, s_c_x, s_s_x, s_x_0, carry);
    SUBCircuit(gc, context, s_x_0, s_p, s_x_1, nonneg);
    ui64 s_x_sel;
    ORGate(gc, context, carry, nonneg, s_x_sel);
    MUXCircuit(gc, context, s_x_0, s_x_1, s_x_sel, s_x);
    s_x.resize(n);
}


void B2ACircuit(GarbledCircuit *gc, BuildContext *context,
        const uv64& s_p, const uv64& s_x, const uv64& s_s_x, uv64& s_c_x) {
    ui64 n = s_c_x.size();
    uv64 s_c_x_0, s_c_x_1;
    ui64 carry, nonneg;
    ADDCircuit(gc, context, s_x, s_s_x, s_c_x_0, carry);
    SUBCircuit(gc, context, s_c_x_0, s_p, s_c_x_1, nonneg);
    ui64 s_c_x_sel;
    ORGate(gc, context, carry, nonneg, s_c_x_sel);
    MUXCircuit(gc, context, s_c_x_0, s_c_x_1, s_c_x_sel, s_c_x);
    s_c_x.resize(n);
}

void ReLUCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& s_p,
        const uv64& s_p_2, const uv64& s_c_x, const uv64& s_s_x, const uv64& s_s_y,
        uv64& s_c_y) {
    uv64 s_x, s_y;
    A2BCircuit(gc, context, s_p, s_c_x, s_s_x, s_x);
    MAXCircuit(gc, context, s_x, s_p_2, s_y);
    B2ACircuit(gc, context, s_p, s_y, s_s_y, s_c_y);
}

void Pool2Circuit(GarbledCircuit *gc, BuildContext *context, const uv64& s_p,
        const uv64& s_p_2, const std::vector<uv64>& s_c_x,
        const std::vector<uv64>& s_s_x, const uv64& s_s_y, uv64& s_c_y) {
    std::vector<uv64> s_x(4);
    uv64 s_in = s_p_2;
    uv64 s_out;
    for(ui64 i=0; i<4; i++){
        A2BCircuit(gc, context, s_p, s_c_x[i], s_s_x[i], s_x[i]);
        MAXCircuit(gc, context, s_x[i], s_in, s_out);
        s_in = s_out;
    }
    B2ACircuit(gc, context, s_p, s_out, s_s_y, s_c_y);
}

ui64 fill_vector(uv64& v, ui64 start){
    ui64 count = start;
    for(ui64 i=0; i<v.size(); i++){
        v[i] = count;
        count++;
    }

    return count;
}

void buildRELULayer(GarbledCircuit& gc, BuildContext& context,
        ui64 width, ui64 n_circ, ui64 p) {
    std::vector<uv64> in(3, uv64(width));
    uv64 out(width);
    uv64 s_p(width), s_p_2(width);

    int n = n_circ*width*3;
    int m = n_circ*width;

    startBuilding(&gc, &context, n, m, n_circ*1000);
    gc.n_c = n_circ*width;
    CONSTCircuit(&gc, &context, p, width, s_p);
    CONSTCircuit(&gc, &context, p/2, width, s_p_2);
    for(ui64 i=0; i<n_circ; i++){
        for(ui64 j=0; j<3; j++){
            fill_vector(in[j], (j*n_circ+i)*width);
        }
        ReLUCircuit(&gc, &context, s_p, s_p_2, in[0], in[1], in[2], out);
        addOutputs(&gc, &context, out);
    }
    finishBuilding(&gc, &context);

    return;
}

void buildPool2Layer(GarbledCircuit& gc, BuildContext& context,
        ui64 width, ui64 n_circ, ui64 p) {
    std::vector<uv64> c_x(4, uv64(width));
    std::vector<uv64> s_x(4, uv64(width));
    uv64 s_y(width);
    uv64 c_y(width);

    int n = n_circ*width*9;
    int m = n_circ*width;

    startBuilding(&gc, &context, n, m, n_circ*2200);
    gc.n_c = 4*n_circ*width;
    uv64 s_p, s_p_2;
    CONSTCircuit(&gc, &context, p, width, s_p);
    CONSTCircuit(&gc, &context, p/2, width, s_p_2);
    for(ui64 i=0; i<n_circ; i++){
        for(ui64 j=0; j<4; j++){
            fill_vector(c_x[j], (j*n_circ+i)*width);
            fill_vector(s_x[j], ((4+j)*n_circ+i)*width);
        }
        fill_vector(s_y, (8*n_circ+i)*width);
        Pool2Circuit(&gc, &context, s_p, s_p_2, c_x, s_x, s_y, c_y);
        addOutputs(&gc, &context, c_y);
    }
    finishBuilding(&gc, &context);

    return;
}

void relu_ref(uv64& din, uv64& dref, ui64 mask, ui64 p){
    dref[0] = (std::max((din[0] + din[1]) % p, p/2) + din[2]) % p;
}

void pool2_ref(uv64& din, uv64& dref, ui64 mask, ui64 p){
    ui64 curr_max = 0;
    curr_max = std::max((din[0] + din[4]) % p, p/2);
    curr_max = std::max((din[1] + din[5]) % p, curr_max);
    curr_max = std::max((din[2] + din[6]) % p, curr_max);
    curr_max = std::max((din[3] + din[7]) % p, curr_max);
    dref[0] = (curr_max + din[8]) % p;
}

}
