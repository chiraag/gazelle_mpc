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

#ifndef GATES_H_
#define GATES_H_

#include <stdexcept>
#include "gc.h"

namespace lbcrypto {

void genericGate(GarbledCircuit *gc, BuildContext *context, ui64 in0, ui64 in1, ui64& out, ui64 type);

inline ui64 fixedZeroWire(GarbledCircuit *gc, BuildContext *garblingContext) {
    return gc->n;
}

inline ui64 fixedOneWire(GarbledCircuit *gc, BuildContext *garblingContext) {
    return (gc->n + 1);
}

inline void NOTGate(GarbledCircuit *gc, BuildContext *context, ui64 in, ui64& out) {
    return genericGate(gc, context, in, (gc->n + 1), out, XORGATE);
}

inline void ANDGate(GarbledCircuit *gc, BuildContext *context, ui64 in0, ui64 in1, ui64& out) {
    return genericGate(gc, context, in0, in1, out, ANDGATE);
}

inline void ORGate(GarbledCircuit *gc, BuildContext *context, ui64 in0, ui64 in1, ui64& out) {
    return genericGate(gc, context, in0, in1, out, ORGATE);
}

inline void XORGate(GarbledCircuit *gc, BuildContext *context, ui64 in0, ui64 in1, ui64& out) {
    return genericGate(gc, context, in0, in1, out, XORGATE);
}

inline void XNORGate(GarbledCircuit *gc, BuildContext *context, ui64 in0, ui64 in1, ui64& out) {
    return genericGate(gc, context, in0, in1, out, XNORGATE);
}

}

#endif /* GATES_H_ */