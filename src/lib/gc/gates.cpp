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
#include "gates.h"

namespace lbcrypto {

void genericGate(GarbledCircuit *gc, BuildContext *context, ui64 in0, ui64 in1, ui64& output, ui64 type) {
    GarbledGate *garbledGate = &(gc->garbledGates[context->gateIndex]);
    output = context->wireIndex;

    garbledGate->type = type;
    garbledGate->input0 = in0;
    garbledGate->input1 = in1;
    garbledGate->output = output;

    if(in0 >= output || in1 >= output){
        std::cout << in0 << " " << in1 << " " << output << std::endl;
        throw std::logic_error("bad circuit");
    }

    context->wireIndex++;
    context->gateIndex++;
    if(type != XORGATE && type != XNORGATE){
        context->tableIndex++;
    }
}

}