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

#ifndef CIRCUITS_H_
#define CIRCUITS_H_

#include "gc.h"

namespace lbcrypto {

void CONSTCircuit(GarbledCircuit *gc, BuildContext *context, ui64 p, ui64 width, uv64& out);

void ANDTreeCircuit(GarbledCircuit *gc, BuildContext *context, uv64& in, ui64& out);
void ORCircuit(GarbledCircuit *gc, BuildContext *context, ui64 n, ui64* inputs, ui64* outputs);

void XORCircuit(GarbledCircuit *gc, BuildContext *context, ui64 n, ui64* inputs, ui64* outputs);
void XORCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, uv64& out);
void ANDCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, uv64& out);
void ORCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, uv64& out);
void NOTCircuit(GarbledCircuit *gc, BuildContext *context, uv64& in, uv64& out);
void MIXEDCircuit(GarbledCircuit *gc, BuildContext *context, ui64 n, ui64* inputs, ui64* outputs);

void SHLCircuit(GarbledCircuit *gc, BuildContext *context, uv64& in, ui64 shift, uv64& out);
void SHRCircuit(GarbledCircuit *gc, BuildContext *context, uv64& in, ui64 shift, uv64& out);

void ADD32Circuit(GarbledCircuit *gc, BuildContext *context, ui64 a, ui64 b, ui64 cin, ui64& s, ui64& cout);
void ADD22Circuit(GarbledCircuit *gc, BuildContext *context, ui64 a, ui64 b, ui64& s, ui64& cout);
void SUB32Circuit(GarbledCircuit *gc,BuildContext *context, ui64 a, ui64 b, ui64 cin, ui64& s, ui64& cout);

void INCCircuit(GarbledCircuit *gc, BuildContext *context, uv64& in, uv64& out, ui64& carry);
void ADDCircuit(GarbledCircuit *gc, BuildContext *context,
        const uv64& in_a, const uv64& in_b, uv64& out, ui64& carry);
void SUBSlowCircuit(GarbledCircuit *gc, BuildContext *context, uv64& in_a, uv64& in_b, uv64& out, ui64& carry);
void SUBCircuit(GarbledCircuit *gc, BuildContext *context,
        const uv64& in_a, const uv64& in_b, uv64& out, ui64& carry);

void EQUCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, ui64& out);
void LEQCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, ui64& out);
void GEQCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, ui64& out);
void LESCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, ui64& out);
void GRECircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, ui64& out);

void MUXCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in0,
        const uv64& in1, const ui64 sel, uv64& out);
void MINCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, uv64& out);
void MAXCircuit(GarbledCircuit *gc, BuildContext *context, const uv64& in_a, const uv64& in_b, uv64& out);

// ui64 MULCircuit(GarbledCircuit *gc, GarblingContext *context, ui64 n, ui64* inputs, ui64* outputs);

void MultiXORCircuit(GarbledCircuit *gc, BuildContext *context, ui64 d, ui64 n, ui64* inputs, ui64* outputs);


void EncoderCircuit(GarbledCircuit *gc, BuildContext *context,  ui64* inputs, ui64* outputs, ui64 enc[]);
void EncoderOneCircuit(GarbledCircuit *gc, BuildContext *context,   ui64* inputs, ui64* outputs, ui64 enc[]);

void RANDCircuit(GarbledCircuit *garbledCircuit, BuildContext *context, ui64 n, ui64* inputs, ui64* outputs, ui64 q, ui64 qf);

void buildTestCircuit(GarbledCircuit& garbledCircuit, BuildContext& context);

}

#endif /* CIRCUITS_H_ */
