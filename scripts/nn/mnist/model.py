import torch.nn as nn
from collections import OrderedDict
import torch.utils.model_zoo as model_zoo
from utee import misc
from utee import act
print = misc.logger.info

model_urls = {
    'mnist': 'http://ml.cs.tsinghua.edu.cn/~chenxi/pytorch-models/mnist.pth',
    'mnist_secure_ml': 'mnist_secure_ml.pth',
    'mnist_cryptonets': 'mnist_cryptonets.pth',
    'mnist_deepsecure': 'mnist_deepsecure.pth',
    'mnist_minionn': 'mnist_minionn.pth',
}

class MNIST(nn.Module):
    def __init__(self):
        super(MNIST, self).__init__()

        self.features = nn.Sequential()
        self.classifier = nn.Sequential(
            nn.Linear(28*28, 256), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(256, 256), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(256, 10)
        )

        print(self.features)
        print(self.classifier)

    def forward(self, x):
        x = self.features(x)
        x = x.view(x.size(0), -1)
        x = self.classifier(x)
        return x

class MNISTCryptoNets(nn.Module):
    def __init__(self):
        super(MNISTCryptoNets, self).__init__()

        self.features = nn.Sequential(
            nn.Conv2d(1, 5, 5, 2, 2), act.Square()
        )

        self.classifier = nn.Sequential(
            nn.Linear(980, 100), act.Square(), # nn.Dropout(0.2),
            nn.Linear(100, 10)
        )

        print(self.features)
        print(self.classifier)

    def forward(self, x):
        x = self.features(x)
        x = x.view(x.size(0), -1)
        # print("Num features", list(x.size()))
        x = self.classifier(x)
        return x

class MNISTDeepSecure(nn.Module):
    def __init__(self):
        super(MNISTDeepSecure, self).__init__()

        self.features = nn.Sequential(
            nn.Conv2d(1, 5, 5, 2, 2), nn.ReLU()
        )

        self.classifier = nn.Sequential(
            nn.Linear(980, 100), nn.ReLU(), # nn.Dropout(0.2),
            nn.Linear(100, 10)
        )

        print(self.features)
        print(self.classifier)

    def forward(self, x):
        x = self.features(x)
        x = x.view(x.size(0), -1)
        # print("Num features", list(x.size()))
        x = self.classifier(x)
        return x

class MNISTMiniONN(nn.Module):
    def __init__(self):
        super(MNISTMiniONN, self).__init__()

        self.features = nn.Sequential(
            nn.Conv2d(1, 16, 5),
            nn.ReLU(), nn.MaxPool2d(2),
            nn.Conv2d(16, 16, 5, 1),
            nn.ReLU(), nn.MaxPool2d(2)
        )

        self.classifier = nn.Sequential(
            nn.Linear(256, 100), nn.ReLU(), # nn.Dropout(0.2),
            nn.Linear(100, 10)
        )

        print(self.features)
        print(self.classifier)

    def forward(self, x):
        x = self.features(x)
        x = x.view(x.size(0), -1)
        x = self.classifier(x)
        return x

class MNISTSecureML(nn.Module):
    def __init__(self):
        super(MNISTSecureML, self).__init__()

        self.features = nn.Sequential()
        self.classifier = nn.Sequential(
            nn.Linear(28*28, 128), act.Square(), nn.Dropout(0.2),
            nn.Linear(128, 128), act.Square(), nn.Dropout(0.2),
            nn.Linear(128, 10)
        )

        print(self.features)
        print(self.classifier)

    def forward(self, x):
        x = self.features(x)
        x = x.view(x.size(0), -1)
        x = self.classifier(x)
        return x

def get(model_name, model_dir, pretrained=False):
    if model_name == 'mnist':
        model = MNIST()
    elif model_name == 'mnist_secure_ml':
        model = MNISTSecureML()
    elif model_name == 'mnist_cryptonets':
        model = MNISTCryptoNets()
    elif model_name == 'mnist_deepsecure':
        model = MNISTDeepSecure()
    elif model_name == 'mnist_minionn':
        model = MNISTMiniONN()
    else:
        assert False, model_name

    if pretrained:
        m = model_zoo.load_url(model_urls[model_name], model_dir)
        state_dict = m.state_dict() if isinstance(m, nn.Module) else m
        assert isinstance(state_dict, (dict, OrderedDict)), type(state_dict)
        model.load_state_dict(state_dict)
    return model

