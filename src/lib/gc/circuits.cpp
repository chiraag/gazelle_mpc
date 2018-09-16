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


#include "gc.h"
#include "util.h"
#include "gates.h"
#include "circuits.h"

namespace lbcrypto {

void CONSTCircuit(GarbledCircuit *gc, BuildContext *garblingContext, ui64 p, ui64 width, uv64& out){
    out.resize(width);
    for(ui64 i=0; i<width; i++){
        out[i] = gc->n + (p & 1);
        p = p >> 1;
    }
}


void ANDTreeCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, uv64& in, ui64& out) {
    ui64 curr_in = in[0];
    ui64 curr_out = 0;

    for (ui64 i = 1; i < in.size(); i++) {
        ANDGate(garbledCircuit, garblingContext, curr_in, in[i], curr_out);
        curr_in = curr_out;
    }
    out = curr_out;
}


void XORCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        ui64 n, ui64* inputs, ui64* outputs) {
    ui64 i;
    ui64 internalWire;
    ui64 split = n / 2;
    for (i = 0; i < n / 2; i++) {
        XORGate(garbledCircuit, garblingContext, inputs[i],
                inputs[split + i], internalWire);
        outputs[i] = internalWire;
    }
}

void XORCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& out) {
    ui64 n = in_a.size();
    out.resize(n);

    for (ui64 i = 0; i < n; i++) {
        XORGate(garbledCircuit, garblingContext, in_a[i], in_b[i], out[i]);
    }
}


void ANDCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& out) {
    ui64 n = in_a.size();
    out.resize(n);

    for (ui64 i = 0; i < n; i++) {
        ANDGate(garbledCircuit, garblingContext, in_a[i], in_b[i], out[i]);
    }
}


void ORCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& out) {
    ui64 n = in_a.size();
    out.resize(n);

    for (ui64 i = 0; i < n; i++) {
        ORGate(garbledCircuit, garblingContext, in_a[i], in_b[i], out[i]);
    }
}


void MIXEDCircuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 n, ui64* inputs, ui64* outputs) {
    ui64 i;
    ui64 oldInternalWire = inputs[0];
    ui64 newInternalWire;

    for (i = 0; i < n - 1; i++) {
        if (i % 3 == 2)
            ORGate(garbledCircuit, garblingContext, inputs[i + 1],
                    oldInternalWire, newInternalWire);
        if (i % 3 == 1)
            ANDGate(garbledCircuit, garblingContext, inputs[i + 1],
                    oldInternalWire, newInternalWire);
        if (i % 3 == 0)
            XORGate(garbledCircuit, garblingContext, inputs[i + 1],
                    oldInternalWire, newInternalWire);
        oldInternalWire = newInternalWire;
    }
    outputs[0] = oldInternalWire;
}

void EncoderCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs, ui64 enc[]) {
    ui64 i, j, temp;
    ui64 n = 8;
    ui64 curWires[n];
    for (i = 0; i < n; i++) {
        curWires[i] = fixedZeroWire(gc, garblingContext);
    }
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            if (fbits(enc[i],j)) {
                XORGate(gc, garblingContext, curWires[j], inputs[i], temp);
                curWires[j] = temp;
            }
        }
    }
    for (i = 0; i < n; i++) {
        outputs[i] = curWires[i];
    }
}
void EncoderOneCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs, ui64 enc[]) {
    ui64 i, j, temp;
    ui64 n = 8;
    ui64 curWires[n];
    for (i = 0; i < n; i++) {
        curWires[i] = fixedOneWire(gc, garblingContext);
    }
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            if (fbits(enc[i],j)) {
                XORGate(gc, garblingContext, curWires[j], inputs[i], temp);
                curWires[j] = temp;
            }
        }
    }
    for (i = 0; i < n; i++) {
        outputs[i] = curWires[i];
    }
}

void RANDCircuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 n, ui64* inputs, ui64* outputs,
        ui64 q, ui64 qf) {
    ui64 i;
    ui64 oldInternalWire;
    ui64 newInternalWire;

    ANDGate(garbledCircuit, garblingContext, 0, 1, oldInternalWire);

    for (i = 2; i < q + qf - 1; i++) {
        if (i < q)
            ANDGate(garbledCircuit, garblingContext, i % n, oldInternalWire,
                    newInternalWire);
        else
            XORGate(garbledCircuit, garblingContext, i % n, oldInternalWire,
                    newInternalWire);
        oldInternalWire = newInternalWire;
    }
    outputs[0] = oldInternalWire;
}

void INCCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        uv64& in, uv64& out, ui64& carry) {
    ui64 n = in.size();
    out.resize(n);

    NOTGate(garbledCircuit, garblingContext, in[0], out[0]);
    ui64 cin = in[0];
    ui64 cout;
    for (ui64 i = 1; i < n; i++) {
        XORGate(garbledCircuit, garblingContext, in[i], cin, out[i]);
        ANDGate(garbledCircuit, garblingContext, in[i], cin, cout);
        cin = cout;
    }
    carry = cin;
}

void SUBSlowCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        uv64& in_a, uv64& in_b, uv64& out, ui64& nonneg) {
    ui64 n = in_a.size();
    out.resize(n);

    uv64 not_b, minus_b;
    ui64 zero, carry;
    NOTCircuit(garbledCircuit, garblingContext, in_b, not_b);
    INCCircuit(garbledCircuit, garblingContext, not_b, minus_b, zero);
    ADDCircuit(garbledCircuit, garblingContext, in_a, minus_b, out, carry);

    // Fix the borrow for in_b == 0
    XORGate(garbledCircuit, garblingContext, zero, carry, nonneg);
}

void SHLCircuit(GarbledCircuit *gc, BuildContext *garblingContext, uv64& in, ui64 shift, uv64& out) {
    ui64 n = in.size();
    out.resize(n);
    for(ui64 i=0; i<shift; i++){
        out[i] = fixedZeroWire(gc, garblingContext);
    }
    for(ui64 i=shift; i<n; i++){
        out[i] = in[i-1];
    }
}

void SHRCircuit(GarbledCircuit *gc, BuildContext *garblingContext, uv64& in, ui64 shift, uv64& out) {
    ui64 n = in.size();
    out.resize(n);
    for(ui64 i=0; i<(n-shift); i++){
        out[i] = in[i+1];
    }
    for(ui64 i=(n-shift); i<n; i++){
        out[i] = fixedZeroWire(gc, garblingContext);
    }
}

/* ui64 MULCircuit(GarbledCircuit *garbledCircuit, GarblingContext *garblingContext,
        ui64 nt, ui64* inputs, ui64* outputs) {
    ui64 i, j;
    ui64 n = nt / 2;
    ui64 *A = inputs;
    ui64 *B = inputs + n;

    ui64 tempAnd[n][2 * n];
    ui64 tempAddIn[4 * n];
    ui64 tempAddOut[4 * n + 1];

    for (i = 0; i < n; i++) {
        for (j = 0; j < i; j++) {
            tempAnd[i][j] = fixedZeroWire(garbledCircuit, garblingContext);
        }
        for (j = i; j < i + n; j++) {
            tempAnd[i][j] = getNextWire(garblingContext);
            ANDGate(garbledCircuit, garblingContext, A[j - i], B[i],
                    tempAnd[i][j]);
        }
        for (j = i + n; j < 2 * n; j++)
            tempAnd[i][j] = fixedZeroWire(garbledCircuit, garblingContext);
    }

    for (j = 0; j < 2 * n; j++) {
        tempAddOut[j] = tempAnd[0][j];
    }
    for (i = 1; i < n; i++) {
        for (j = 0; j < 2 * n; j++) {
            tempAddIn[j] = tempAddOut[j];
        }
        for (j = 2 * n; j < 4 * n; j++) {
            tempAddIn[j] = tempAnd[i][j - 2 * n];
        }
        ADDCircuit(garbledCircuit, garblingContext, 4 * n, tempAddIn,
                tempAddOut);
    }
    for (j = 0; j < 2 * n; j++) {
        outputs[j] = tempAddOut[j];
    }
    return 0;

} */

void MUXCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        const uv64& in0, const uv64& in1, ui64 sel, uv64& out) {
    ui64 n = in1.size();
    out.resize(n);

    uv64 sum(n), prod(n);
    for (ui64 i = 0; i < n; i++) {
        XORGate(gc, garblingContext, in0[i], in1[i], sum[i]);
        ANDGate(gc, garblingContext, sum[i], sel, prod[i]);
        XORGate(gc, garblingContext, in0[i], prod[i], out[i]);
    }
}

void MINCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& out) {
    ui64 leq;
    LEQCircuit(gc, garblingContext, in_a, in_b, leq);
    MUXCircuit(gc, garblingContext, in_b, in_a, leq, out);
}

void MAXCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& out) {
    ui64 leq;
    LEQCircuit(gc, garblingContext, in_a, in_b, leq);
    MUXCircuit(gc, garblingContext, in_a, in_b, leq, out);
}

void EQUCircuit(GarbledCircuit *gc, BuildContext *garblingContext, const uv64& in_a, const uv64& in_b, ui64& out) {
    uv64 xor_w;
    XORCircuit(gc, garblingContext, in_a, in_b, xor_w);
    ANDTreeCircuit(gc, garblingContext, xor_w, out);
}

void GEQCircuit(GarbledCircuit *gc, BuildContext *garblingContext, const uv64& in_a, const uv64& in_b, ui64& out) {
    uv64 sub_w;
    SUBCircuit(gc, garblingContext, in_a, in_b, sub_w, out);
}

void LESCircuit(GarbledCircuit *gc, BuildContext *garblingContext, const uv64& in_a, const uv64& in_b, ui64& out) {
    ui64 geq;
    GEQCircuit(gc, garblingContext, in_b, in_a, geq);
    NOTGate(gc, garblingContext, geq, out);
}

void GRECircuit(GarbledCircuit *gc, BuildContext *garblingContext, const uv64& in_a, const uv64& in_b, ui64& out) {
    LESCircuit(gc, garblingContext, in_b, in_a, out);
}

void LEQCircuit(GarbledCircuit *gc, BuildContext *garblingContext, const uv64& in_a, const uv64& in_b, ui64& out) {
    GEQCircuit(gc, garblingContext, in_b, in_a, out);
}

void NOTCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        uv64& in, uv64& out) {
    ui64 n = in.size();
    out.resize(n);
    for (ui64 i = 0; i < n; i++) {
        NOTGate(garbledCircuit, garblingContext, in[i], out[i]);
    }
}

void ADDCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& out, ui64& carry) {
    ui64 n = in_a.size();
    out.resize(n);

    ui64 cin, cout;
    ADD22Circuit(garbledCircuit, garblingContext, in_a[0], in_b[0], out[0], cout);

    for (ui64 i = 1; i < n; i++) {
        cin = cout;
        ADD32Circuit(garbledCircuit, garblingContext, in_a[i], in_b[i], cin, out[i], cout);
    }
    carry = cout;
}

void SUBCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        const uv64& in_a, const uv64& in_b, uv64& diff, ui64& nonneg) {
    ui64 n = in_a.size();
    diff.resize(n);

    ui64 c_cin = fixedOneWire(garbledCircuit, garblingContext);
    ui64 c_cout;

    for (ui64 i = 0; i < n; i++) {
        SUB32Circuit(garbledCircuit, garblingContext, in_a[i], in_b[i], c_cin, diff[i], c_cout);
        c_cin = c_cout;
    }
    nonneg = c_cout;
}

void SUB32Circuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 a, ui64 b, ui64 cin, ui64& s, ui64& cout){
    ui64 hs, w1, w2;

    XNORGate(garbledCircuit, garblingContext, a, b, hs);
    XORGate(garbledCircuit, garblingContext, cin, hs, s);

    XORGate(garbledCircuit, garblingContext, cin, a, w1);
    ANDGate(garbledCircuit, garblingContext, w1, hs, w2);
    XORGate(garbledCircuit, garblingContext, a, w2, cout);
}

void ADD32Circuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 a, ui64 b, ui64 cin, ui64& s, ui64& cout){
    ui64 hs, w1, w2;

    XORGate(garbledCircuit, garblingContext, a, b, hs);
    XORGate(garbledCircuit, garblingContext, cin, hs, s);
    
    XORGate(garbledCircuit, garblingContext, cin, a, w1);
    ANDGate(garbledCircuit, garblingContext, w1, hs, w2);
    XORGate(garbledCircuit, garblingContext, a, w2, cout);
}

void ADD22Circuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 a, ui64 b, ui64& s, ui64& cout) {
    XORGate(garbledCircuit, garblingContext, a, b, s);
    ANDGate(garbledCircuit, garblingContext, a, b, cout);
}

void ORCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        ui64 n, ui64* inputs, ui64* outputs) {
    ui64 i;
    ui64 oldInternalWire;
    ui64 newInternalWire;
    ORGate(garbledCircuit, garblingContext, inputs[0], inputs[1],
            oldInternalWire);
    for (i = 2; i < n - 1; i++) {
        ORGate(garbledCircuit, garblingContext, inputs[i], oldInternalWire,
                newInternalWire);
        oldInternalWire = newInternalWire;
    }
    ORGate(garbledCircuit, garblingContext, inputs[n - 1], oldInternalWire, outputs[0]);
}

void MultiXORCircuit(GarbledCircuit *gc, BuildContext *garblingContext, ui64 d,
        ui64 n, ui64* inputs, ui64* outputs) {
    ui64 i, j;
    ui64 div = n / d;

    ui64 tempInWires[n];
    ui64 tempOutWires[n];
    for (i = 0; i < div; i++) {
        tempOutWires[i] = inputs[i];
    }

    for (i = 1; i < d; i++) {
        for (j = 0; j < div; j++) {
            tempInWires[j] = tempOutWires[j];
            tempInWires[div + j] = inputs[div * i + j];
        }
        XORCircuit(gc, garblingContext, 2 * div, tempInWires, tempOutWires);
    }
    for (i = 0; i < div; i++) {
        outputs[i] = tempOutWires[i];
    }

}

void buildTestCircuit(GarbledCircuit& garbledCircuit, BuildContext& garblingContext) {
    ui64 width = 2;
    uv64 in_a(width), in_b(width);
    for(ui64 i=0; i<width; i++){
        in_a[i] = i;
        in_b[i] = width+i;
    }
    uv64 out(width);
    ui64 carry;

    ui64 n = width*2;
    ui64 m = width;

    startBuilding(&garbledCircuit, &garblingContext, n, m);
    ADDCircuit(&garbledCircuit, &garblingContext, in_a, in_b, out, carry);
    addOutputs(&garbledCircuit, &garblingContext, out);
    finishBuilding(&garbledCircuit, &garblingContext);
}

}
