from analyzer.utils import Contract, get_code_from_adr
import pandas as pd
import os
df = pd.read_csv('target_tx.csv')
groups = df.groupby('entrypoint')

flag = False
for entrypoint, group in groups:
    print('searching', entrypoint)
    try:
        c = get_code_from_adr(entrypoint)
    except:
        continue
#     print('searching', entrypoint)
    if c.abi != 'none':
        path = './entrypoint'
        if not os.path.exists(path):
            os.mkdir(path)
        group.to_csv(os.path.join(path, '{}.csv'.format(entrypoint)))
