from utee import misc
import os
print = misc.logger.info
from IPython import embed

def load(model_name, dataset_name, model_root):
    if dataset_name == 'mnist':
        from mnist import dataset, model
        f = dataset.get
        m = model.get(model_name, model_root)
    elif dataset_name == 'svhn':
        from svhn import dataset, model
        f = dataset.get
        m = model.get(model_name, model_root)
    elif dataset_name == 'cifar10':
        from cifar import dataset, model
        f = dataset.get10
        m = model.get(model_name, model_root)
    elif dataset_name == 'cifar100':
        from cifar import dataset, model
        f = dataset.get100
        m = model.get(model_name, model_root)
    elif dataset_name == 'stl10':
        from stl10 import dataset, model
        f = dataset.get
        m = model.get(model_name, model_root)
    elif dataset_name == 'imagenet':
        from imagenet import dataset, model
        f = dataset.get
        m = model.get(model_name, model_root)
    else:
        print('Dataset not implemented')
    return f(**kwargs), model

if __name__ == '__main__':
    m1 = alexnet()
    embed()
