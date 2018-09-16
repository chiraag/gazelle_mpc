/*
 * aescircuits.h
 *
 *  Created on: Dec 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_GC_AESCIRCUITS_H_
#define SRC_LIB_GC_AESCIRCUITS_H_

namespace lbcrypto {

void SBOXNOTABLE(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void AddRoundKey(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void SubBytes(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void SubBytesTable(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void ShiftRows(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void MixColumns(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void MULTE_GF16(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void INV_GF16(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void AFFINE(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void SBOX(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void INVMAP(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);
void GF8MULCircuit(GarbledCircuit *garbledCircuit, BuildContext *garblingContext, ui64 n, ui64* inputs, ui64* outputs);

void GF4MULCircuit(GarbledCircuit *gc, BuildContext *garblingContext,  ui64* inputs, ui64* outputs);
void GF4SQCircuit(GarbledCircuit *gc, BuildContext *garblingContext,  ui64* inputs, ui64* outputs);
void GF4SCLNCircuit(GarbledCircuit *gc, BuildContext *garblingContext,  ui64* inputs, ui64* outputs);
void GF4SCLN2Circuit(GarbledCircuit *gc, BuildContext *garblingContext,  ui64* inputs, ui64* outputs);

void NewSBOXCircuit(GarbledCircuit *gc, BuildContext *garblingContext, ui64* inputs, ui64* outputs);

void buildAESCircuit(GarbledCircuit& garbledCircuit, BuildContext& garblingContext);

}

#endif /* SRC_LIB_GC_AESCIRCUITS_H_ */
