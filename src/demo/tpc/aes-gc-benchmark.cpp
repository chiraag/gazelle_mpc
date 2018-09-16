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
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>

#include "gc/gc.h"
#include "gc/util.h"
#include "gc/aescircuits.h"
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;
using namespace lbcrypto;

std::string AES_CIRCUIT_FILE_NAME = "./aesCircuit";

unsigned long timedEval(GarbledCircuit *garbledCircuit, InputLabels& inputLabels) {

    int n = garbledCircuit->n;
    int m = garbledCircuit->m;
    ExtractedLabels extractedLabels(n);
    OutputLabels outputs(m);
    int j;
    InputMap inputs(n);
    unsigned long startTime, endTime;
    unsigned long sum = 0;
    for (j = 0; j < n; j++) {
        inputs[j] = rand() % 2;
    }
    extractLabels(extractedLabels, inputLabels, inputs);
    startTime = RDTSC;
    evaluate(garbledCircuit, extractedLabels, outputs);
    endTime = RDTSC;
    sum = endTime - startTime;
    return sum;

}

int main() {
    int rounds = 10;
    int n = 128 + (128 * rounds);
    int m = 128;

    GarbledCircuit aesCircuit;
    BuildContext context;
    buildAESCircuit(aesCircuit, context);

    InputLabels inputLabels(n);
    OutputMap outputMap(m);
    int i, j;

    int timeGarble[TIMES];
    int timeEval[TIMES];
    double timeGarbleMedians[TIMES];
    double timeEvalMedians[TIMES];
    garbleCircuit(&aesCircuit, inputLabels, outputMap);

    for (j = 0; j < TIMES; j++) {
        for (i = 0; i < TIMES; i++) {
            timeGarble[i] = garbleCircuit(&aesCircuit, inputLabels, outputMap);
            timeEval[i] = timedEval(&aesCircuit, inputLabels);
        }
        timeGarbleMedians[j] = ((double) median(timeGarble, TIMES))
                / aesCircuit.q;
        timeEvalMedians[j] = ((double) median(timeEval, TIMES)) / aesCircuit.q;
    }
    double garblingTime = doubleMean(timeGarbleMedians, TIMES);
    double evalTime = doubleMean(timeEvalMedians, TIMES);
    std::cout << garblingTime << " " << evalTime << std::endl;
    return 0;
}
