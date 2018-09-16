#include "circuits.h"
#include "gates.h"
#include "util.h"
#include "aes.h"
#include "gc.h"
#include <time.h>

#include <iostream>

namespace lbcrypto {

unsigned long startTime, endTime;

int startBuilding(GarbledCircuit *gc, BuildContext *context, long n, long m, long q) {
    startTime = RDTSC;
    gc->m = m;
    gc->n = n;
    gc->outputs.resize(m);

    // Speculative defaults. TODO: Add dynamic resizing
    gc->q = q;
    gc->r = n+q+2;
    gc->garbledGates.resize(gc->q);
    gc->wires.resize(gc->r);

    context->outputIndex = 0;
    context->gateIndex = 0;
    context->tableIndex = 0;
    context->wireIndex = gc->n + 2;

    return 0;
}

void addOutputs(GarbledCircuit *gc, BuildContext *context, uv64& outputs) {
    for (ui64 i = 0; i < outputs.size(); i++) {
        gc->outputs[context->outputIndex] = outputs[i];
        context->outputIndex++;
    }
}

int finishBuilding(GarbledCircuit *gc, BuildContext *context) {
    gc->q = context->gateIndex;
    gc->r = gc->n+gc->q+2;

    gc->wires.resize(gc->r);
    gc->garbledGates.resize(gc->q);
    gc->garbledTable.resize(context->tableIndex);

    endTime = RDTSC;
    return (int) (endTime - startTime);
}

block createInputLabels(GarbledCircuit *gc, InputLabels& inputLabels) {
    block R = randomBlock();
    short* pR_16 = (short *) (&R);
    *pR_16 |= 1;

    block* rand_context = getRandContext();
    for (int i = 0; i < (gc->n+2); i ++) {
        randAESBlock(&gc->wires[i].label0, rand_context);
        gc->wires[i].label1 = xorBlocks(R, gc->wires[i].label0);

        if(i < gc->n) {
            inputLabels[i][0] = gc->wires[i].label0;
            inputLabels[i][1] = gc->wires[i].label1;
        }
    }

    return R;
}

long garbleCircuit(GarbledCircuit *gc, InputLabels& inputLabels, OutputMap& outputMap) {
    GarbledGate *garbledGate;

    seedRandom();

    unsigned long startTime = RDTSC;

    auto R = createInputLabels(gc, inputLabels);
    auto& garbledTable = gc->garbledTable;

    block table_key = randomBlock();
    gc->table_key = table_key;
    AES_KEY KT;
    AESInit(&table_key, &KT);

    block label_key = randomBlock();
    AES_KEY KL;
    AESInit(&label_key, &KL);

    long lsb0, lsb1;
    int input0, input1, output;
    long tableIndex = 0;
    for (long i = 0; i < gc->q; i++) {
        garbledGate = &(gc->garbledGates[i]);
        input0 = garbledGate->input0;
        input1 = garbledGate->input1;
        output = garbledGate->output;

        if (garbledGate->type == XORGATE) {
            gc->wires[output].label0 =
                    xorBlocks(gc->wires[input0].label0, gc->wires[input1].label0);
            gc->wires[output].label1 =
                    xorBlocks(gc->wires[input0].label1, gc->wires[input1].label0);

            // std::cout << "g " << garbledGate->output << " " << garbledCircuit->wires[output].label0
            //      << " " << garbledCircuit->wires[output].label1 << std::endl;
        } else if (garbledGate->type == XNORGATE) {
            gc->wires[output].label0 =
                    xorBlocks(gc->wires[input0].label1, gc->wires[input1].label0);
            gc->wires[output].label1 =
                    xorBlocks(gc->wires[input0].label0, gc->wires[input1].label0);
        } else {
            // Get lsb of the zero labels
            lsb0 = getLSB(gc->wires[input0].label0);
            lsb1 = getLSB(gc->wires[input1].label0);
            long g_lsb = ((garbledGate->type >> (2*lsb0 + lsb1)) & 1);
            long alpha_a = ((garbledGate->type >> 4) & 1);
            long alpha_b = ((garbledGate->type >> 5) & 1);

            // Hash all the labels
            block HA0, HA1, HB0, HB1;
            {
                block tweak[2];
                block masks[4], keys[4];

                tweak[0] = makeBlock(2 * i, (uint64_t) 0);
                tweak[1] = makeBlock(2 * i + 1, (uint64_t) 0);

                masks[0] = keys[0] = xorBlocks(DOUBLE(gc->wires[input0].label0), tweak[0]);
                masks[1] = keys[1] = xorBlocks(DOUBLE(gc->wires[input0].label1), tweak[0]);
                masks[2] = keys[2] = xorBlocks(DOUBLE(gc->wires[input1].label0), tweak[1]);
                masks[3] = keys[3] = xorBlocks(DOUBLE(gc->wires[input1].label1), tweak[1]);
                AES_ecb_encrypt_blks_4(keys, &KT);
                HA0 = xorBlocks(keys[0], masks[0]);
                HA1 = xorBlocks(keys[1], masks[1]);
                HB0 = xorBlocks(keys[2], masks[2]);
                HB1 = xorBlocks(keys[3], masks[3]);
            }

            block tmp, W0;

            // Generator Half Gate
            garbledTable[tableIndex].table[0] = xorBlocks(HA0, HA1);
            if (lsb1 != alpha_b)
                garbledTable[tableIndex].table[0] = xorBlocks(garbledTable[tableIndex].table[0], R);
            W0 = (lsb0) ? HA1 : HA0;

            // Evaluator Half Gate
            tmp = (alpha_a) ? gc->wires[input0].label1 : gc->wires[input0].label0;
            garbledTable[tableIndex].table[1] = xorBlocks(tmp, xorBlocks(HB0, HB1));
            W0 = xorBlocks(W0, ((lsb1) ? HB1 : HB0));

            // Finalize label
            if(g_lsb) {
                gc->wires[garbledGate->output].label0 = xorBlocks(W0, R);
                gc->wires[garbledGate->output].label1 = W0;
            } else {
                gc->wires[garbledGate->output].label0 = W0;
                gc->wires[garbledGate->output].label1 = xorBlocks(W0, R);
            }

            tableIndex++;
        }
    }

    for (long i = 0; i < gc->m; i++) {
        outputMap[i] = getLSB(gc->wires[gc->outputs[i]].label0);
    }
    unsigned long endTime = RDTSC;
    return (endTime - startTime);
}

void extractLabels(ExtractedLabels& extractedLabels, InputLabels& inputLabels,
        InputMap& inputBits) {
    ui64 n = extractedLabels.size();
    for (ui64 i = 0; i < n; i++) {
        extractedLabels[i] = inputLabels[i][inputBits[i]];
    }
}

int evaluate(GarbledCircuit *garbledCircuit, ExtractedLabels& extractedLabels,
        OutputLabels& outputLabels) {
    GarbledGate *garbledGate;
    AES_KEY dkCipherContext;
    AESInit(&(garbledCircuit->table_key), &dkCipherContext);
    for (long i = 0; i < garbledCircuit->n; i++) {
        garbledCircuit->wires[i].label = extractedLabels[i];
    }

    block A, B;
    long a, b;
    auto& garbledTable = garbledCircuit->garbledTable;
    garbledCircuit->wires[garbledCircuit->n].label = garbledCircuit->wires[garbledCircuit->n].label0;
    garbledCircuit->wires[garbledCircuit->n+1].label = garbledCircuit->wires[garbledCircuit->n+1].label1;
    int tableIndex = 0;

    for (long i = 0; i < garbledCircuit->q; i++) {
        garbledGate = &(garbledCircuit->garbledGates[i]);
        if (garbledGate->type == XORGATE || garbledGate->type == XNORGATE) {
            garbledCircuit->wires[garbledGate->output].label =
            xorBlocks(garbledCircuit->wires[garbledGate->input0].label,
                    garbledCircuit->wires[garbledGate->input1].label);

            // std::cout << "ev " << garbledGate->output << " " << garbledCircuit->wires[garbledGate->output].label << std::endl;

        } else {
            A = garbledCircuit->wires[garbledGate->input0].label;
            B = garbledCircuit->wires[garbledGate->input1].label;

            block HA, HB, W;
            block tweak1, tweak2;

            a = getLSB(A);
            b = getLSB(B);

            tweak1 = makeBlock(2 * i, (long) 0);
            tweak2 = makeBlock(2 * i + 1, (long) 0);

            {
                block keys[2];
                block masks[2];

                keys[0] = xorBlocks(DOUBLE(A), tweak1);
                keys[1] = xorBlocks(DOUBLE(B), tweak2);
                masks[0] = keys[0];
                masks[1] = keys[1];
                AES_ecb_encrypt_blks(keys, 2, &dkCipherContext);
                HA = xorBlocks(keys[0], masks[0]);
                HB = xorBlocks(keys[1], masks[1]);

                // HA = E_KT(2*A ^ TA) ^ 2*A ^ TA
            }

            W = xorBlocks(HA, HB);
            if (a)
                W = xorBlocks(W, garbledTable[tableIndex].table[0]);
            if (b) {
                W = xorBlocks(W, garbledTable[tableIndex].table[1]);
                W = xorBlocks(W, A);
            }
            garbledCircuit->wires[garbledGate->output].label = W;

            tableIndex++;
        }
    }

    for (long i = 0; i < garbledCircuit->m; i++) {
        outputLabels[i] = garbledCircuit->wires[garbledCircuit->outputs[i]].label;
    }
    return 0;

}

int evaluate_pt(GarbledCircuit *garbledCircuit, InputMap& inputMap,
        OutputMap& outputMap) {
    osuCrypto::BitVector wires(garbledCircuit->r);
    for (long i = 0; i < garbledCircuit->n; i++) {
        wires[i] = inputMap[i];
    }
    wires[garbledCircuit->n] = 0;
    wires[garbledCircuit->n + 1] = 1;

    GarbledGate *garbledGate;
    int a = 0, b = 0;

    for (long i = 0; i < garbledCircuit->q; i++) {
        garbledGate = &(garbledCircuit->garbledGates[i]);
        a = wires[garbledGate->input0];
        b = wires[garbledGate->input1];

        int c = ((garbledGate->type >> (2*a + b)) & 1);
        wires[garbledGate->output] = c;
    }

    for (long i = 0; i < garbledCircuit->m; i++) {
        outputMap[i] = wires[garbledCircuit->outputs[i]];
    }
    return 0;

}

void mapOutputs(OutputMap& outputMap, OutputLabels& outputLabels, OutputMap& extractedMap){
    ui64 m = outputLabels.size();
    for(ui64 i=0; i<m; i++){
        extractedMap[i] = outputMap[i] ^ getLSB(outputLabels[i]);
    }
}

void pack_inputs(std::vector<uv64>& din, InputMap& inputMap, ui64 width){
    ui32 n_circ = din.size();
    ui32 in_args = din[0].size();
    assert(n_circ*in_args*width == inputMap.size());

    for(ui32 i=0; i<n_circ; i++){
        for(ui32 j=0; j<in_args; j++){
            for(ui32 k=0; k<width; k++){
                inputMap[(j*n_circ+i)*width+k] = ((din[i][j] >> k) & 1);
            }
        }
    }

    return;
}

void unpack_outputs(OutputMap& outputMap, std::vector<uv64>& dout, ui64 width){
    ui32 n_circ = dout.size();
    ui32 out_args = dout[0].size();
    assert(n_circ*out_args*width == outputMap.size());

    for(ui32 i=0; i<n_circ; i++){
        for(ui32 j=0; j<out_args; j++){
            for(ui32 k=0; k<width; k++){
                dout[i][j] |= (outputMap[(j*n_circ+i)*width+k] << k);
            }
        }
    }
    return;
}

void print_results(std::vector<uv64>& din, std::vector<uv64>& dout_pt, 
        std::vector<uv64>& dout, std::vector<uv64>& dref){
    ui32 n_circ = din.size();
    ui32 in_args = din[0].size();
    ui32 out_args = dout[0].size();

    for(ui32 i=0; i<n_circ; i++){
        std::cout << i << ": (";
        for (ui32 j=0; j<in_args; j++){
            std::cout << din[i][j];
            if (j != in_args-1){
                std::cout << ", ";
            }
        }
        std::cout << ") -> (";
        for (ui32 j=0; j<out_args; j++){
            std::cout << dout_pt[i][j];
            if (j != out_args-1){
                std::cout << ", ";
            }
        }
        std::cout << ") (";
        for (ui32 j=0; j<out_args; j++){
            std::cout << dout[i][j];
            if (j != out_args-1){
                std::cout << ", ";
            }
        }
        std::cout << ") [ref: (";
        for (ui32 j=0; j<out_args; j++){
            std::cout << dref[i][j];
            if (j != out_args-1){
                std::cout << ", ";
            }
        }
        std::cout << ")]" << std::endl;

        assert(dref[i] == dout_pt[i]);
        assert(dref[i] == dout[i]);
    }

    return;
}

}