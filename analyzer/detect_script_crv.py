import os
import pandas as pd
source_path = './entrypoint'
from analyzer.detection_rules import analyze_with_no_abi
import json
total_contracts_with_abi = sorted(os.listdir(source_path))
target_contract_json_path = 'crv_contract.json'
suspicious_path = 'suspicious/crv'

target_signatures = [
    "3883e119", #// calc_token_amount(uint256[3] amounts,bool deposit )
    "cf701ff7", #// calc_token_amount(uint256[4] amounts,bool deposit )
    "ed8e84f3", #// calc_token_amount(uint256[2] amounts,bool deposit )
    "cc2b27d7", #// calc_withdraw_one_coin(uint256 _token_amount,int128 i )
    "c532a774", #// calc_withdraw_one_coin(uint256 _token_amount,int128 i,bool _use_underlying )
    "41b028f3", #// calc_withdraw_one_coin(address _pool,uint256 _token_amount,int128 i )
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

for contract in total_contracts_with_abi:
    df = pd.read_csv(os.path.join(source_path, contract))
    if found_sig_in_df(df, target_signatures):
        target_contract.append(contract)

f = open(target_contract_json_path, 'w')
f.write(json.dumps(target_contract))

print('contracts with target sig:', len(target_contract))

def log_suspicious(log):
    with open(os.path.join(suspicious_path, '{}.log'.format(tx)), 'a') as f:
        f.write('{}\n'.format(json.dumps(log)))

for contract in target_contract:
    try:
        df = pd.read_csv(os.path.join(source_path, contract))
        for tx in get_first_ditinct_tx(df['tx_hash'].values, 4):
            analyze_with_no_abi(tx, log_suspicious)
    except Exception as e:
        print(e)