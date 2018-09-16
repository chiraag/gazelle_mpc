from utee import misc, compress
import torch
import torch.backends.cudnn as cudnn
import os
cudnn.benchmark =True
from IPython import embed

params = {
    'dataset': 'mnist',
    'model': 'mnist_cryptonets',
    'batch_size': 100,
    'seed': 117,
    'model_dir': './pretrained_models',
    'data_dir': 'dataset/',
    'n_sample': 20,
    'weight_bits': 6,
    'act_bits': 9,
    'overflow_rate': 0.0
}

misc.ensure_dir(params['model_dir'])
params['model_dir'] = misc.expand_user(params['model_dir'])
params['data_dir'] = misc.expand_user(params['data_dir'])

print("================PARAMS==================")
for k, v in params.items():
    print('{}: {}'.format(k, v))
print("========================================")

assert torch.cuda.is_available(), 'no cuda'
torch.manual_seed(params['seed'])
torch.cuda.manual_seed(params['seed'])

# load model and dataset fetcher
model_raw, ds_fetcher = misc.load_model(params['model'], params['dataset'],
        model_root=params['model_dir'], pretrained=True)
model_raw.cuda()
model_raw.eval()

model_new = compress.CompressedModel(model_raw, input_scale=255,
        act_bits=params['act_bits'], weight_bits=params['weight_bits'])
model_new = model_new.cuda()
print(model_new)

val_ds = ds_fetcher(params['batch_size'], data_root=params['data_dir'], train=False)
acc1, acc5 = misc.eval_model(model_new, val_ds, ngpu=1, n_sample=params['n_sample'], is_imagenet=False)
print("FP accuracy Top1: %g Top5: %g" % (acc1, acc5))

model_new.quantize_params()
acc1, acc5 = misc.eval_model(model_new, val_ds, ngpu=1, n_sample=params['n_sample'], is_imagenet=False)
print("Quant accuracy Top1: %g Top5: %g" % (acc1, acc5))
print(acc1, acc5)

print(model_new)
new_file = os.path.join(params['model_dir'],
        '{}-{}bit.pth'.format(params['model'], params['act_bits']))
misc.model_snapshot(model_new, new_file, old_file=None, verbose=True)

#embed()
