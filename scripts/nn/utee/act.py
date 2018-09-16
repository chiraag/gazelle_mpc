import torch
import torch.nn as nn

class Square(nn.Module):
    def __init__(self):
        super(Square, self).__init__()

    def forward(self, x):
        # unfortunately we don't have automatic broadcasting yet
        return torch.mul(x, x)
