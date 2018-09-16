import math

import torch
from torch import nn
from utee import act
from torch.autograd import Variable
from collections import OrderedDict
import numpy as np

def compute_integral_part(in_act, overflow_rate):
    abs_value = in_act.abs().view(-1)
    sorted_value = abs_value.sort(dim=0, descending=True)[0]
    split_idx = int(overflow_rate * len(sorted_value))
    v = sorted_value[split_idx]
    if isinstance(v, Variable):
        v = v.data.cpu().numpy()[0]
    # Add one to allow for sign bit
    sf = math.ceil(math.log2(v+1e-12)) + 1
    return sf

def linear_quantize(in_act, shift, bits, floor=False):
    assert bits >= 1, bits
    if bits == 1:
        return torch.sign(in_act) - 1
    scale = 2**(bits-shift)
    if floor:
        rounded = torch.floor(in_act * scale)
    else:
        rounded = torch.round(in_act * scale)
    clipped_value = torch.clamp(rounded, -2**(bits-1), 2**(bits-1)-1)
    return clipped_value

class DownShift(nn.Module):
    def __init__(self, name, act_bits, overflow_rate=0.0):
        super(DownShift, self).__init__()
        self.name = name
        self.act_bits = act_bits
        self.overflow_rate = overflow_rate
        self.register_buffer('bitwidth', torch.Tensor(1))
        self.bitwidth.fill_(-65)
        self.register_buffer('range', torch.Tensor(2))
        self.range[0] = 1000
        self.range[1] = -1000
        self.bitwidth_delta = 0
        self.shift = 0
        self.final = False

    def forward(self, in_act):
        if self.final:
            output = linear_quantize(in_act, self.bitwidth[0], self.act_bits, floor=True)
            # print(float(np.min(in_act.data.cpu().numpy())))
            self.range[0] = min(self.range[0], float(np.min(output.data.cpu().numpy())))
            self.range[1] = max(self.range[1], float(np.max(output.data.cpu().numpy())))
            return output
            # return output*(2**(self.bitwidth[0]+1-self.act_bits-self.bitwidth_delta))
        else:
            bitwidth_new = compute_integral_part(in_act, self.overflow_rate)
            self.bitwidth[0] = max(self.bitwidth[0], bitwidth_new)
            return in_act

    def finalize(self, bitwidth_delta=0):
        self.final = True
        self.bitwidth[0] += bitwidth_delta
        self.bitwidth_delta = bitwidth_delta
        self.shift = self.bitwidth[0] - self.act_bits
        return (self.act_bits+bitwidth_delta-self.bitwidth[0])

    def reset(self):
        self.final = False

    def __repr__(self):
        return '{}(range=({}, {}) bitwidth={} (shift={}), act_bits={}, overflow_rate={:.3f}, final={})'.format(
            self.__class__.__name__, self.range[0], self.range[1],
            self.bitwidth[0], self.shift, self.act_bits, self.overflow_rate, self.final)

class CompressedModel(nn.Module):
    def __init__(self, model, input_scale=1, act_bits=8, weight_bits=8,
            pretrained=None):
        super(CompressedModel, self).__init__()
        self.input_scale = input_scale
        self.act_bits = act_bits
        self.weight_bits = weight_bits

        if pretrained is None:
            self.remove_batchnorm(model)
            self.add_quant_layers()
        else:
            self.load_params(model, pretrained)

    def load_params_seq(self, seq, pretrained):
        layers = OrderedDict()
        for k, layer in seq._modules.items():
            if not isinstance(layer, (nn.BatchNorm1d, nn.BatchNorm2d)):
                layers[k] = layer
            if isinstance(layer, (nn.Conv2d, nn.Linear, nn.AvgPool2d, act.Square)):
                quant_layer = DownShift('{}_shift'.format(k), act_bits=self.act_bits)
                quant_layer.finalize()
                layers['{}_shift'.format(k)] = quant_layer
        return nn.Sequential(layers)

    def load_params(self, model, pretrained):
        self.features = self.load_params_seq(model.features, pretrained)
        self.classifier = self.load_params_seq(model.classifier, pretrained)
        self.load_state_dict(pretrained)

    def remove_batchnorm_seq(self, seq):
        layers = []
        for layer in seq:
            if not isinstance(layer, (nn.BatchNorm1d, nn.BatchNorm2d)):
                layers.append(layer)
                if 'bias' in layers[-1].state_dict():
                    layers[-1].bias.data = self.input_scale*layers[-1].bias.data
            else:
                scale = torch.rsqrt(layer.running_var + 1e-5)
                layers[-1].weight.data = layers[-1].weight.data*scale[:, None, None, None]
                layers[-1].bias.data = (layers[-1].bias.data - self.input_scale*layer.running_mean)*scale
        return nn.Sequential(*layers)

    def remove_batchnorm(self, model):
        self.features = self.remove_batchnorm_seq(model.features)
        self.classifier = self.remove_batchnorm_seq(model.classifier)

    def add_quant_layers(self, overflow_rate=0.0):
        """Assumes original model has features nn.Sequential"""
        for seq in ['features', 'classifier']:
            l = OrderedDict()
            for k, layer in self._modules[seq]._modules.items():
                l[k] = layer
                if isinstance(layer, (nn.Conv2d, nn.Linear, nn.AvgPool2d, act.Square)):
                    quant_layer = DownShift('{}_shift'.format(k), act_bits=self.act_bits, overflow_rate=overflow_rate)
                    l['{}_shift'.format(k)] = quant_layer
            self._modules[seq] = nn.Sequential(l)

    def quantize_layer(self, layer, in_size=0):
        w_size = compute_integral_part(layer.weight, overflow_rate=0.0)
        layer.weight.data = linear_quantize(layer.weight.data, w_size, self.weight_bits)
        b_size = self.weight_bits - w_size + in_size
        layer.bias.data = torch.round(layer.bias.data*(2**b_size))
        return b_size

    def quantize_params(self, overflow_rate=0.0):
        in_size = 0
        print("Quantizing:")
        for seq in ['features', 'classifier']:
            l = OrderedDict()
            for k, layer in self._modules[seq]._modules.items():
                if isinstance(layer, (nn.Conv2d, nn.Linear)):
                    b_size = self.quantize_layer(layer, in_size)
                    in_size = self._modules[seq]._modules['{}_shift'.format(k)].finalize(b_size)
                    print(k, layer, b_size, in_size)
                    # in_size = 0
                elif isinstance(layer, (nn.AvgPool2d)):
                    in_size = self._modules[seq]._modules['{}_shift'.format(k)].finalize(in_size)
                    print(k, layer, 0, in_size)
                elif isinstance(layer, (act.Square)):
                    in_size = self._modules[seq]._modules['{}_shift'.format(k)].finalize(in_size*2)
                    print(k, layer, 0, in_size)

    def forward(self, x):
        x = self.features(self.input_scale*x)
        x = x.view(x.size(0), -1)
        x = self.classifier(x)
        return x
