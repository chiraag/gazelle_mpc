
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
#include "util.h"
#include "circuits.h"
#include "aescircuits.h"

namespace lbcrypto {

/*******
 * These AES circuits were modeled after the AES circuits of
 * the MPC system due to
 * Huang, Evans, Katz and Malka, available at mightbeevil.org
 */

ui64 A2X1[8] = { 0x98, 0xF3, 0xF2, 0x48, 0x09, 0x81, 0xA9, 0xFF }, X2A1[8] = {
        0x64, 0x78, 0x6E, 0x8C, 0x68, 0x29, 0xDE, 0x60 }, X2S1[8] = { 0x58,
        0x2D, 0x9E, 0x0B, 0xDC, 0x04, 0x03, 0x24 }, S2X1[8] = { 0x8C, 0x79,
        0x05, 0xEB, 0x12, 0x04, 0x51, 0x53 };



ui64 AESSBOXTABLE[] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30,
        0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa,
        0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
        0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b,
        0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53,
        0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a,
        0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
        0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd,
        0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64,
        0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46,
        0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7,
        0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65,
        0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8,
        0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48,
        0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce,
        0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41,
        0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

void AddRoundKey(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    XORCircuit(gc, garblingContext, 256, inputs, outputs);
}

void SubBytes(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs,
        ui64* outputs) {
    NewSBOXCircuit(gc, garblingContext, inputs, outputs);
}

void ShiftRows(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs,
        ui64* outputs) {
    ui64 i, j;
    ui64 shiftTable[] = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++)
            outputs[8 * i + j] = inputs[shiftTable[i] * 8 + j];
    }
}

void MixColumns(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 mulOut[4][8];
    unsigned i, j;
    ui64 inp[4][40];

    for (i = 0; i < 4; i++)
        GF8MULCircuit(gc, garblingContext, 8, inputs + 8 * i, mulOut[i]);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 8; j++)
            inp[i][j] = mulOut[i][j];
        for (j = 0; j < 8; j++)
            inp[i][8 + j] = mulOut[(i + 1) % 4][j];
        for (j = 0; j < 8; j++)
            inp[i][16 + j] = inputs[((i + 1) % 4) * 8 + j];
        for (j = 0; j < 8; j++)
            inp[i][24 + j] = inputs[((i + 2) % 4) * 8 + j];
        for (j = 0; j < 8; j++)
            inp[i][32 + j] = inputs[((i + 3) % 4) * 8 + j];
    }

    for (i = 0; i < 4; i++)
        MultiXORCircuit(gc, garblingContext, 5, 40, inp[i], outputs + 8 * i);
}

void MAP(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs,
        ui64* outputs) {

    unsigned char A = 0;
    unsigned char B = 1;
    unsigned char C = 2;
    unsigned char L0 = 3;
    unsigned char L1 = 4;
    unsigned char L3 = 5;
    unsigned char H0 = 6;
    unsigned char H1 = 7;
    unsigned char H2 = 8;

    ui64 tempW[10];

    XORGate(gc, garblingContext, inputs[1], inputs[7], tempW[A]);

    XORGate(gc, garblingContext, inputs[5], inputs[7], tempW[B]);

    XORGate(gc, garblingContext, inputs[4], inputs[6], tempW[C]);

    ui64 temp;
    XORGate(gc, garblingContext, tempW[C], inputs[0], temp);
    XORGate(gc, garblingContext, temp, inputs[5], tempW[L0]);

    XORGate(gc, garblingContext, inputs[1], inputs[2], tempW[L1]);

    XORGate(gc, garblingContext, inputs[4], inputs[2], tempW[L3]);

    XORGate(gc, garblingContext, inputs[5], tempW[C], tempW[H0]);

    XORGate(gc, garblingContext, inputs[A], inputs[C], tempW[H1]);

    ui64 temp2;
    XORGate(gc, garblingContext, tempW[B], inputs[2], temp2);
    XORGate(gc, garblingContext, temp2, inputs[3], tempW[H2]);

    outputs[0] = tempW[L0];
    outputs[1] = tempW[L1];
    outputs[2] = tempW[A];
    outputs[3] = tempW[L3];
    outputs[4] = tempW[H0];
    outputs[5] = tempW[H1];
    outputs[6] = tempW[H2];
    outputs[7] = tempW[B];
}

void INVMAP(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs,
        ui64* outputs) {
    unsigned char A = 0;
    unsigned char B = 1;
    unsigned char a0 = 2;
    unsigned char a1 = 3;
    unsigned char a2 = 4;
    unsigned char a3 = 5;
    unsigned char a4 = 6;
    unsigned char a5 = 7;
    unsigned char a6 = 8;
    unsigned char a7 = 9;

    unsigned char l0 = 0;
    unsigned char l1 = 1;
    unsigned char l2 = 2;
    unsigned char l3 = 3;
    unsigned char h0 = 4;
    unsigned char h1 = 5;
    unsigned char h2 = 6;
    unsigned char h3 = 7;

    ui64 tempW[16];

    XORGate(gc, garblingContext, inputs[l1], inputs[h3], tempW[A]);

    XORGate(gc, garblingContext, inputs[h1], inputs[h0], tempW[B]);

    XORGate(gc, garblingContext, inputs[l0], inputs[h0], tempW[a0]);

    XORGate(gc, garblingContext, inputs[h3], tempW[B], tempW[a1]);

    XORGate(gc, garblingContext, tempW[A], tempW[B], tempW[a2]);

    ui64 temp;
    XORGate(gc, garblingContext, tempW[B], inputs[l1], temp);

    XORGate(gc, garblingContext, temp, inputs[h2], tempW[a3]);

    XORGate(gc, garblingContext, tempW[A], tempW[B], temp);

    XORGate(gc, garblingContext, inputs[l3], temp, tempW[a4]);

    XORGate(gc, garblingContext, inputs[l2], tempW[B], tempW[a5]);

    XORGate(gc, garblingContext, tempW[A], inputs[l2], temp);

    ui64 temp2;
    XORGate(gc, garblingContext, temp, inputs[l3], temp2);
    XORGate(gc, garblingContext, temp2, inputs[h0], tempW[a6]);

    XORGate(gc, garblingContext, tempW[B], inputs[l2], temp2);

    XORGate(gc, garblingContext, temp2, inputs[h3], tempW[a7]);

    outputs[0] = tempW[a0];
    outputs[1] = tempW[a1];
    outputs[2] = tempW[a2];
    outputs[3] = tempW[a3];
    outputs[4] = tempW[a4];
    outputs[5] = tempW[a5];
    outputs[6] = tempW[a6];
    outputs[7] = tempW[a7];
}

void MULTGF16(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs,
        ui64* outputs) {

    unsigned char A = 0;
    unsigned char B = 1;
    unsigned char C = 2;
    unsigned char q0 = 3;
    unsigned char q1 = 4;
    unsigned char q2 = 5;
    unsigned char q3 = 6;

    unsigned char and00 = 7;
    unsigned char and31 = 8;
    unsigned char and22 = 9;
    unsigned char and13 = 10;
    unsigned char and10 = 11;
    unsigned char andA1 = 12;
    unsigned char andB2 = 13;
    unsigned char andC3 = 14;
    unsigned char and20 = 15;
    unsigned char and11 = 16;
    unsigned char andA2 = 17;
    unsigned char andB3 = 18;
    unsigned char and30 = 19;
    unsigned char and21 = 20;
    unsigned char and12 = 21;
    unsigned char andA3 = 22;

    unsigned char b0 = 0;
    unsigned char b1 = 1;
    unsigned char b2 = 2;
    unsigned char b3 = 3;
    unsigned char a0 = 4;
    unsigned char a1 = 5;
    unsigned char a2 = 6;
    unsigned char a3 = 7;

    ui64 tempW[24];

    XORGate(gc, garblingContext, inputs[a3], inputs[a0], tempW[A]);

    XORGate(gc, garblingContext, inputs[a3], inputs[a2], tempW[B]);

    XORGate(gc, garblingContext, inputs[a1], inputs[a2], tempW[C]);

    ANDGate(gc, garblingContext, inputs[a0], inputs[b0], tempW[and00]);

    ANDGate(gc, garblingContext, inputs[a3], inputs[b1], tempW[and31]);

    ANDGate(gc, garblingContext, inputs[a2], inputs[b2], tempW[and22]);

    ANDGate(gc, garblingContext, inputs[a1], inputs[b3], tempW[and13]);

    ui64 temp1, temp2;
    XORGate(gc, garblingContext, tempW[and00], tempW[and31], temp1);

    XORGate(gc, garblingContext, tempW[and13], tempW[and22], temp2);
    XORGate(gc, garblingContext, temp1, temp2, tempW[q0]);

    ANDGate(gc, garblingContext, inputs[a1], inputs[b0], tempW[and10]);

    ANDGate(gc, garblingContext, tempW[A], inputs[b1], tempW[andA1]);

    ANDGate(gc, garblingContext, tempW[B], inputs[b2], tempW[andB2]);

    ANDGate(gc, garblingContext, tempW[C], inputs[b3], tempW[andC3]);

    XORGate(gc, garblingContext, tempW[and10], tempW[andA1], temp1);

    XORGate(gc, garblingContext, tempW[andB2], tempW[andC3], temp2);

    XORGate(gc, garblingContext, temp1, temp2, tempW[q1]);

    ANDGate(gc, garblingContext, inputs[a2], inputs[b0], tempW[and20]);

    ANDGate(gc, garblingContext, inputs[a1], inputs[b1], tempW[and11]);

    ANDGate(gc, garblingContext, tempW[A], inputs[b2], tempW[andA2]);

    ANDGate(gc, garblingContext, tempW[B], inputs[b3], tempW[andB3]);

    XORGate(gc, garblingContext, tempW[and20], tempW[and11], temp1);

    XORGate(gc, garblingContext, tempW[andA2], tempW[andB3], temp2);

    XORGate(gc, garblingContext, temp1, temp2, tempW[q2]);

    ANDGate(gc, garblingContext, inputs[a3], inputs[b0], tempW[and30]);

    ANDGate(gc, garblingContext, inputs[a2], inputs[b1], tempW[and21]);

    ANDGate(gc, garblingContext, inputs[a1], inputs[b2], tempW[and12]);

    ANDGate(gc, garblingContext, tempW[A], inputs[b3], tempW[andA3]);

    XORGate(gc, garblingContext, tempW[and30], tempW[and21], temp1);

    XORGate(gc, garblingContext, tempW[andA3], tempW[and12], temp2);

    XORGate(gc, garblingContext, temp1, temp2, tempW[q3]);

    outputs[0] = tempW[q0];
    outputs[1] = tempW[q1];
    outputs[2] = tempW[q2];
    outputs[3] = tempW[q3];
}

inline void SquareCircuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 n, ui64* inputs, ui64* outputs) {

    XORGate(garbledCircuit, garblingContext, inputs[0], inputs[2], outputs[0]);
    outputs[1] = inputs[2];
    XORGate(garbledCircuit, garblingContext, inputs[1], inputs[3], outputs[2]);
    outputs[3] = inputs[3];
}

void MULTE_GF16(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 outputA, outputB, outputq0, outputq2, outputq3;

    XORGate(garbledCircuit, garblingContext, inputs[0], inputs[1], outputA);

    XORGate(garbledCircuit, garblingContext, inputs[2], inputs[3], outputB);

    XORGate(garbledCircuit, garblingContext, outputB, inputs[1], outputq0);

    XORGate(garbledCircuit, garblingContext, outputA, inputs[2], outputq2);

    XORGate(garbledCircuit, garblingContext, outputB, outputA, outputq3);

    outputs[0] = outputq0;
    outputs[1] = outputA;
    outputs[2] = outputq2;
    outputs[3] = outputq3;
}

void INV_GF16(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 AOutput, q0Output, q1Output, q2Output, q3Output;

    ui64 and01Output, and02Output, and03Output;
    ui64 and12Output, and13Output, and23Output;
    ui64 and012Output, and123Output, and023Output, and013Output;

    ANDGate(garbledCircuit, garblingContext, inputs[0], inputs[1], and01Output);

    ANDGate(garbledCircuit, garblingContext, inputs[0], inputs[2], and02Output);

    ANDGate(garbledCircuit, garblingContext, inputs[0], inputs[3], and03Output);

    ANDGate(garbledCircuit, garblingContext, inputs[2], inputs[1], and12Output);

    ANDGate(garbledCircuit, garblingContext, inputs[3], inputs[1], and13Output);

    ANDGate(garbledCircuit, garblingContext, inputs[2], inputs[3], and23Output);

    ANDGate(garbledCircuit, garblingContext, inputs[2], and01Output,
            and012Output);

    ANDGate(garbledCircuit, garblingContext, inputs[3], and12Output,
            and123Output);

    ANDGate(garbledCircuit, garblingContext, inputs[3], and02Output,
            and023Output);

    ANDGate(garbledCircuit, garblingContext, inputs[3], and01Output,
            and013Output);

    ui64 tempXORA1;
    XORGate(garbledCircuit, garblingContext, inputs[1], inputs[2], tempXORA1);
    ui64 tempXORA2;
    XORGate(garbledCircuit, garblingContext, inputs[3], and123Output,
            tempXORA2);
    XORGate(garbledCircuit, garblingContext, tempXORA1, tempXORA2, AOutput);

    ui64 tempXORq01;
    ui64 tempXORq02;
    ui64 tempXORq03;

    XORGate(garbledCircuit, garblingContext, inputs[0], AOutput, tempXORq01);
    XORGate(garbledCircuit, garblingContext, and02Output, tempXORq01,
            tempXORq02);
    XORGate(garbledCircuit, garblingContext, and12Output, tempXORq02,
            tempXORq03);
    XORGate(garbledCircuit, garblingContext, and012Output, tempXORq03,
            q0Output);

    ui64 tempXORq11;
    ui64 tempXORq12;
    ui64 tempXORq13;
    ui64 tempXORq14;

    XORGate(garbledCircuit, garblingContext, and01Output, and02Output,
            tempXORq11);
    XORGate(garbledCircuit, garblingContext, and12Output, tempXORq11,
            tempXORq12);
    XORGate(garbledCircuit, garblingContext, inputs[3], tempXORq12, tempXORq13);
    XORGate(garbledCircuit, garblingContext, and13Output, tempXORq13,
            tempXORq14);
    XORGate(garbledCircuit, garblingContext, and013Output, tempXORq14,
            q1Output);

    ui64 tempXORq21;
    ui64 tempXORq22;
    ui64 tempXORq23;
    ui64 tempXORq24;

    XORGate(garbledCircuit, garblingContext, and01Output, inputs[2],
            tempXORq21);
    XORGate(garbledCircuit, garblingContext, and02Output, tempXORq21,
            tempXORq22);
    XORGate(garbledCircuit, garblingContext, inputs[3], tempXORq22, tempXORq23);
    XORGate(garbledCircuit, garblingContext, and03Output, tempXORq23,
            tempXORq24);
    XORGate(garbledCircuit, garblingContext, and023Output, tempXORq24,
            q2Output);

    ui64 tempXORq31;
    ui64 tempXORq32;

    XORGate(garbledCircuit, garblingContext, AOutput, and03Output, tempXORq31);
    XORGate(garbledCircuit, garblingContext, and13Output, tempXORq31,
            tempXORq32);
    XORGate(garbledCircuit, garblingContext, and23Output, tempXORq32, q3Output);

    outputs[0] = q0Output;
    outputs[1] = q1Output;
    outputs[2] = q2Output;
    outputs[3] = q3Output;
}

void AFFINE(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 AOutput;
    ui64 BOutput;
    ui64 COutput;
    ui64 DOutput;

    ui64 q0Output;
    ui64 q1Output;
    ui64 q2Output;
    ui64 q3Output;
    ui64 q4Output;
    ui64 q5Output;
    ui64 q6Output;
    ui64 q7Output;

    ui64 a0barOutput;
    ui64 a1barOutput;
    ui64 a5barOutput;
    ui64 a6barOutput;

    XORGate(garbledCircuit, garblingContext, inputs[0], inputs[1], AOutput);

    XORGate(garbledCircuit, garblingContext, inputs[2], inputs[3], BOutput);

    XORGate(garbledCircuit, garblingContext, inputs[4], inputs[5], COutput);

    XORGate(garbledCircuit, garblingContext, inputs[6], inputs[7], DOutput);

    NOTGate(garbledCircuit, garblingContext, inputs[0], a0barOutput);

    NOTGate(garbledCircuit, garblingContext, inputs[1], a1barOutput);

    NOTGate(garbledCircuit, garblingContext, inputs[5], a5barOutput);

    NOTGate(garbledCircuit, garblingContext, inputs[6], a6barOutput);

    ui64 tempWireq0;
    XORGate(garbledCircuit, garblingContext, a0barOutput, COutput, tempWireq0);
    XORGate(garbledCircuit, garblingContext, tempWireq0, DOutput, q0Output);

    ui64 tempWireq1;
    XORGate(garbledCircuit, garblingContext, a5barOutput, AOutput, tempWireq1);
    XORGate(garbledCircuit, garblingContext, tempWireq1, DOutput, q1Output);

    ui64 tempWireq2;
    XORGate(garbledCircuit, garblingContext, inputs[2], AOutput, tempWireq2);
    XORGate(garbledCircuit, garblingContext, tempWireq2, DOutput, q2Output);

    ui64 tempWireq3;
    XORGate(garbledCircuit, garblingContext, inputs[7], AOutput, tempWireq3);
    XORGate(garbledCircuit, garblingContext, tempWireq3, BOutput, q3Output);

    ui64 tempWireq4;
    XORGate(garbledCircuit, garblingContext, inputs[4], AOutput, tempWireq4);
    XORGate(garbledCircuit, garblingContext, tempWireq4, BOutput, q4Output);

    ui64 tempWireq5;
    XORGate(garbledCircuit, garblingContext, a1barOutput, BOutput, tempWireq5);
    XORGate(garbledCircuit, garblingContext, tempWireq5, COutput, q5Output);

    ui64 tempWireq6;
    XORGate(garbledCircuit, garblingContext, a6barOutput, BOutput, tempWireq6);
    XORGate(garbledCircuit, garblingContext, tempWireq6, COutput, q6Output);

    ui64 tempWireq7;
    XORGate(garbledCircuit, garblingContext, inputs[3], COutput, tempWireq7);
    XORGate(garbledCircuit, garblingContext, tempWireq7, DOutput, q7Output);

    outputs[0] = q0Output;
    outputs[1] = q1Output;
    outputs[2] = q2Output;
    outputs[3] = q3Output;
    outputs[4] = q4Output;
    outputs[5] = q5Output;
    outputs[6] = q6Output;
    outputs[7] = q7Output;
}

void INV_GF256(GarbledCircuit *garbledCircuit, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 i;
    ui64 square0Inputs[8];
    ui64 square0Outputs[8];
    ui64 square1Inputs[8];
    ui64 square1Outputs[8];

    ui64 Mult0Inputs[8];
    ui64 Mult1Inputs[8];
    ui64 XOR0Inputs[8];
    ui64 XOR0Outputs[8];
    ui64 XOR1Inputs[8];
    ui64 XOR1Outputs[8];
    ui64 Mult0Outputs[8];
    ui64 Mult1Outputs[8];

    ui64 mapOutputs[16];

    MAP(garbledCircuit, garblingContext, inputs, mapOutputs);

    for (i = 0; i < 4; i++) {
        square0Inputs[i] = mapOutputs[i + 4];

        square1Inputs[i] = mapOutputs[i];

        Mult0Inputs[i] = mapOutputs[i + 4];

        Mult0Inputs[i + 4] = mapOutputs[i];

        XOR0Inputs[i] = mapOutputs[i + 4];

        XOR0Inputs[i + 4] = mapOutputs[i];
    }

    SquareCircuit(garbledCircuit, garblingContext, 4, square0Inputs,
            square0Outputs);
    SquareCircuit(garbledCircuit, garblingContext, 4, square1Inputs,
            square1Outputs);

    MULTGF16(garbledCircuit, garblingContext, Mult0Inputs, Mult0Outputs);

    XORCircuit(garbledCircuit, garblingContext, 8, XOR0Inputs, XOR0Outputs);

    ui64 MultEInputs[8];
    ui64 MultEOutputs[8];
    ui64 XOR2Inputs[8];
    ui64 XOR2Outputs[8];

    for (i = 0; i < 4; i++) {

        MultEInputs[i] = square0Outputs[i];
        XOR1Inputs[i] = square1Outputs[i];
    }

    MULTE_GF16(garbledCircuit, garblingContext, MultEInputs, MultEOutputs);

    for (i = 0; i < 4; i++) {
        XOR1Inputs[i + 4] = MultEOutputs[i];
    }

    XORCircuit(garbledCircuit, garblingContext, 8, XOR1Inputs, XOR1Outputs);
    for (i = 0; i < 4; i++) {
        XOR2Inputs[i] = Mult0Outputs[i];
        XOR2Inputs[i + 4] = XOR1Outputs[i];
    }
    XORCircuit(garbledCircuit, garblingContext, 8, XOR2Inputs, XOR2Outputs);

    ui64 InvtInputs[8];
    ui64 InvtOutputs[8];

    for (i = 0; i < 4; i++) {
        InvtInputs[i] = XOR2Outputs[i];
    }
    INV_GF16(garbledCircuit, garblingContext, InvtInputs, InvtOutputs);

    for (i = 0; i < 4; i++) {
        Mult1Inputs[i] = InvtOutputs[i];
    }
    for (i = 0; i < 4; i++) {
        Mult1Inputs[i + 4] = mapOutputs[i + 4];
    }
    MULTGF16(garbledCircuit, garblingContext, Mult1Inputs, Mult1Outputs);

    ui64 Mult2Inputs[8];
    ui64 Mult2Outputs[8];
    for (i = 0; i < 4; i++) {
        Mult2Inputs[i] = XOR0Outputs[i];
        Mult2Inputs[i + 4] = InvtOutputs[i];
    }
    MULTGF16(garbledCircuit, garblingContext, Mult2Inputs, Mult2Outputs);

    ui64 InvMapInputs[8];
    ui64 InvMapOutputs[8];

    for (i = 0; i < 4; i++) {
        InvMapInputs[i] = Mult2Outputs[i];
        InvMapInputs[i + 4] = Mult1Outputs[i];
    }

    INVMAP(garbledCircuit, garblingContext, InvMapInputs, InvMapOutputs);
    for (i = 0; i < 8; i++) {
        outputs[i] = InvMapOutputs[i];
    }
}

void SBOXNOTABLE(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64* inputs, ui64* outputs) {

    ui64 invInputs[8];
    ui64 invOutputs[8];
    ui64 i;
    for (i = 0; i < 8; i++)
        invInputs[i] = inputs[i];
    INV_GF256(garbledCircuit, garblingContext, invInputs, invOutputs);
    AFFINE(garbledCircuit, garblingContext, invOutputs, outputs);
}

void GF16SQCLCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 a[2], b[2];
    a[0] = inputs[2];
    a[1] = inputs[3];
    b[0] = inputs[0];
    b[1] = inputs[1];

    ui64 ab[4];
    ab[0] = a[0];
    ab[1] = a[1];
    ab[2] = b[0];
    ab[3] = b[1];

    ui64 tempx[2];
    XORCircuit(gc, garblingContext, 4, ab, tempx);
    ui64 p[2], q[2];
    GF4SQCircuit(gc, garblingContext, tempx, p);
    ui64 tempx2[4];
    GF4SQCircuit(gc, garblingContext, b, tempx2);
    GF4SCLN2Circuit(gc, garblingContext, tempx2, q);

    outputs[0] = q[0];
    outputs[1] = q[1];
    outputs[2] = p[0];
    outputs[3] = p[1];
}

void GF16MULCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 ab[4], cd[4], e[4];
    ab[0] = inputs[2];
    ab[1] = inputs[3];
    ab[2] = inputs[0];
    ab[3] = inputs[1];

    cd[0] = inputs[2 + 4];
    cd[1] = inputs[3 + 4];
    cd[2] = inputs[0 + 4];
    cd[3] = inputs[1 + 4];

    ui64 abcdx[4];
    XORCircuit(gc, garblingContext, 4, ab, abcdx);
    XORCircuit(gc, garblingContext, 4, cd, abcdx + 2);
    GF4MULCircuit(gc, garblingContext, abcdx, e);
    ui64 em[2];
    GF4SCLNCircuit(gc, garblingContext, e, em);
    ui64 p[2], q[2];

    ui64 ac[4];
    ac[0] = ab[0];
    ac[1] = ab[1];
    ac[2] = cd[0];
    ac[3] = cd[1];

    ui64 bd[4];
    bd[0] = ab[2 + 0];
    bd[1] = ab[2 + 1];
    bd[2] = cd[2 + 0];
    bd[3] = cd[2 + 1];

    ui64 tmpx1[4], tmpx2[4];
    GF4MULCircuit(gc, garblingContext, ac, tmpx1);
    GF4MULCircuit(gc, garblingContext, bd, tmpx2);

    tmpx1[2] = em[0];
    tmpx1[3] = em[1];
    tmpx2[2] = em[0];
    tmpx2[3] = em[1];

    XORCircuit(gc, garblingContext, 4, tmpx1, p);
    XORCircuit(gc, garblingContext, 4, tmpx2, q);

    outputs[0] = q[0];
    outputs[1] = q[1];
    outputs[2] = p[0];
    outputs[3] = p[1];
}

void GF4MULCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 a, b, c, d, e, p, q;

    a = inputs[1];
    b = inputs[0];
    c = inputs[3];
    d = inputs[2];
    ui64 temp1;
    XORGate(gc, garblingContext, a, b, temp1);

    ui64 temp2;
    XORGate(gc, garblingContext, c, d, temp2);

    ANDGate(gc, garblingContext, temp1, temp2, e);

    ui64 temp3;
    ANDGate(gc, garblingContext, a, c, temp3);
    XORGate(gc, garblingContext, temp3, e, p);

    ui64 temp4;
    ANDGate(gc, garblingContext, b, d, temp4);
    XORGate(gc, garblingContext, temp4, e, q);

    outputs[1] = p;
    outputs[0] = q;
}

void GF4SCLNCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {

    XORGate(gc, garblingContext, inputs[0], inputs[1], outputs[0]);
    outputs[1] = inputs[0];
}

void GF4SQCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {

    outputs[0] = inputs[1];
    outputs[1] = inputs[0];
}

void GF16INVCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {

    ui64 a[2], b[2];
    a[0] = inputs[2];
    a[1] = inputs[3];
    b[0] = inputs[0];
    b[1] = inputs[1];

    ui64 ab[4], cd[4];
    ab[0] = a[0];
    ab[1] = a[1];
    ab[2] = b[0];
    ab[3] = b[1];

    ui64 tempx[2], tempxs[2];
    XORCircuit(gc, garblingContext, 4, ab, tempx);
    GF4SQCircuit(gc, garblingContext, tempx, tempxs);

    ui64 c[2], d[2], e[2], p[2], q[2];
    GF4SCLNCircuit(gc, garblingContext, tempxs, c);

    GF4MULCircuit(gc, garblingContext, ab, d);

    cd[0] = c[0];
    cd[1] = c[1];
    cd[2] = d[0];
    cd[3] = d[1];

    ui64 tempx2[2];
    XORCircuit(gc, garblingContext, 4, cd, tempx2);
    GF4SQCircuit(gc, garblingContext, tempx2, e);
    ui64 eb[4], ea[4];
    ea[0] = e[0];
    ea[1] = e[1];
    ea[2] = a[0];
    ea[3] = a[1];

    eb[0] = e[0];
    eb[1] = e[1];
    eb[2] = b[0];
    eb[3] = b[1];

    GF4MULCircuit(gc, garblingContext, eb, p);
    GF4MULCircuit(gc, garblingContext, ea, q);

    outputs[0] = q[0];
    outputs[1] = q[1];
    outputs[2] = p[0];
    outputs[3] = p[1];
}

void GF256InvCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 A[4], B[4], C[4], D[4], E[4], P[4], Q[4], tempX[4];
    ui64 i;
    for (i = 0; i < 4; i++) {
        A[i] = inputs[i];
        B[i] = inputs[i + 4];
    }

    XORCircuit(gc, garblingContext, 8, inputs, tempX);
    GF16SQCLCircuit(gc, garblingContext, tempX, C);
    GF16MULCircuit(gc, garblingContext, inputs, D);

    ui64 CD[8];
    for (i = 0; i < 4; i++) {
        CD[i] = C[i];
        CD[i + 4] = D[i];
    }
    ui64 tempX2[4];
    XORCircuit(gc, garblingContext, 8, CD, tempX2);
    GF16INVCircuit(gc, garblingContext, tempX2, E);
    ui64 EB[8];
    for (i = 0; i < 4; i++) {
        EB[i] = E[i];
        EB[i + 4] = B[i];
    }

    ui64 EA[8];
    for (i = 0; i < 4; i++) {
        EA[i] = E[i];
        EA[i + 4] = A[i];
    }

    GF16MULCircuit(gc, garblingContext, EB, P);
    GF16MULCircuit(gc, garblingContext, EA, Q);

    outputs[4] = P[0];
    outputs[5] = P[1];
    outputs[6] = P[2];
    outputs[7] = P[3];

    outputs[0] = Q[0];
    outputs[1] = Q[1];
    outputs[2] = Q[2];
    outputs[3] = Q[3];
}

void NewSBOXCircuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {
    ui64 temp1[8], temp2[8]/*, temp3[8]*/;
    EncoderCircuit(gc, garblingContext, inputs, temp1, A2X1);
    GF256InvCircuit(gc, garblingContext, temp1, temp2);
    EncoderOneCircuit(gc, garblingContext, temp2, outputs, S2X1);
}

void GF4SCLN2Circuit(GarbledCircuit *gc, BuildContext *garblingContext,
        ui64* inputs, ui64* outputs) {

    XORGate(gc, garblingContext, inputs[0], inputs[1], outputs[1]);
    outputs[0] = inputs[1];
}


//http://edipermadi.files.wordpress.com/2008/02/aes_galois_field.jpg

void GF8MULCircuit(GarbledCircuit *garbledCircuit,
        BuildContext *garblingContext, ui64 n, ui64* inputs, ui64* outputs) {

    outputs[0] = inputs[7];
    outputs[2] = inputs[1];
    XORGate(garbledCircuit, garblingContext, inputs[7], inputs[2], outputs[3]);

    XORGate(garbledCircuit, garblingContext, inputs[7], inputs[3], outputs[4]);

    outputs[5] = inputs[4];
    outputs[6] = inputs[5];
    outputs[7] = inputs[6];
    XORGate(garbledCircuit, garblingContext, inputs[7], inputs[0], outputs[1]);
}


void buildAESCircuit(GarbledCircuit& garbledCircuit, BuildContext& garblingContext) {
    srand(time(NULL));

    ui64 roundLimit = 10;
    ui64 n = 128 * (roundLimit + 1);
    ui64 m = 128;
    // int q = 50000; //Just an upper bound
    ui64 addKeyInputs[256];
    ui64 addKeyOutputs[128];
    ui64 subBytesOutputs[128];
    ui64 shiftRowsOutputs[128];
    ui64 mixColumnOutputs[128];

    startBuilding(&garbledCircuit, &garblingContext, n, m);
    countToN(addKeyInputs, 256);
    for (ui64 round = 0; round < roundLimit; round++) {

        AddRoundKey(&garbledCircuit, &garblingContext, addKeyInputs,
                addKeyOutputs);

        for (ui64 i = 0; i < 16; i++) {
            SubBytes(&garbledCircuit, &garblingContext, addKeyOutputs + 8 * i,
                    subBytesOutputs + 8 * i);
        }

        ShiftRows(&garbledCircuit, &garblingContext, subBytesOutputs,
                shiftRowsOutputs);

        for (ui64 i = 0; i < 4; i++) {
            if (round != roundLimit - 1)
                MixColumns(&garbledCircuit, &garblingContext,
                        shiftRowsOutputs + i * 32, mixColumnOutputs + 32 * i);
        }
        for (ui64 i = 0; i < 128; i++) {
            addKeyInputs[i] = mixColumnOutputs[i];
            addKeyInputs[i + 128] = 128 + (round + 1) * 128 + i;
        }
    }

    uv64 final(m);
    for(ui64 i=0; i<m; i++){
        final[i] = mixColumnOutputs[i];
    }
    addOutputs(&garbledCircuit, &garblingContext, final);
    finishBuilding(&garbledCircuit, &garblingContext);
}

}