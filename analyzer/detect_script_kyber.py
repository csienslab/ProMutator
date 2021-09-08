import os
import pandas as pd
source_path = './entrypoint'
from analyzer.detection_rules import analyze_with_no_abi
import json
total_contracts_with_abi = sorted(os.listdir(source_path))
target_contract_json_path = 'kyber_contract.json'
suspicious_path = 'suspicious/kyber'

target_signatures = [
    "809a9e55", #// expected
]


def get_first_ditinct_tx(txs, count):
    distinct_txs = []
    for tx in txs:
        if tx not in distinct_txs:
            distinct_txs.append(tx)
            if len(distinct_txs) >= count:
                return distinct_txs
    return distinct_txs

def found_sig_in_df(df, target_sigs):
    if 'signature' not in df.columns:
        return False
    
    for s in target_sigs:
        for i in df['signature'].values:
            if i.find(s) > -1:
                return True
    return False

target_contract = []

# if not os.path.exists(target_contract_json_path):

for contract in total_contracts_with_abi:
    df = pd.read_csv(os.path.join(source_path, contract))
    if found_sig_in_df(df, target_signatures):
        target_contract.append(contract)

f = open(target_contract_json_path, 'w')
f.write(json.dumps(target_contract))
# else:
#     f = open(target_contract_json_path, 'r')
#     target_contract = json.loads(f.read())

print('contracts with target sig:', len(target_contract))

def log_suspicious(log):
    with open(os.path.join(suspicious_path, '{}.log'.format(tx)), 'a') as f:
        f.write('{}\n'.format(json.dumps(log)))

for contract in target_contract:
    df = pd.read_csv(os.path.join(source_path, contract))
    for tx in get_first_ditinct_tx(df['tx_hash'].values, 2):
        analyze_with_no_abi(tx, log_suspicious)
