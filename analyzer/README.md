# Setup
0. install requirements.
```sh
pip install -r requirements.txt
```
1. open mutator-geth and sync the node.
```sh
../go-ethereum/build/bin/geth --syncmode full --gcmode archive
```
2. open `analyzer/config.py` and set geth endpoint and etherscan api key.
Please register and get a api key at `https://etherscan.io/apis`. 

```python
WEB3_IPC_PATH = '/home/.ethereum/geth.ipc'
ETHERSCAN_API_KEY = ''
```
# Pre processing

Mutator anaylzes one transaction at a time.  We first collect transactions using tracers.

```sh
python3 extracter.py {start_block} {end_block}
```

This collects target transactions that call price oracle related functions.
Modify `extracter.js` to collect more funtions. Transaction information are logged in `./target_tx.csv`


We can not mutate function input of the transaction that calls a closed source contract.
We remove closed source contracts in this step. ** Note: this step is optional as we can still apply two mutation rules for close source contracts**

```sh
python3 get_contract_with_abi.py
```

# Mutate

**Detection rules: crv**
```sh
python3 detect_script_crv.py
```

Target at `calc_token_amount`, `calc_withdraw_one_coin`.
Output: `suspicious/crv`

**Detection rules: kyber**
```sh
python3 detect_script_kyber.py
```

Target at `getExpectedRate`
Output: `suspicious/kyber`

**Detection rules: uniswap**
```sh
python3 detect_script_uniswap.py
```
Target at `getReserve`
Output: `suspicious/uniswap`

**Detection rules: mutate input**
```
python3 detect_script_mutate_input.py
```

Mutate function input.
This mutation rules only support open source contracts.

## Analyze single transaction
We can analyze one transaction at a time.  This is a demo that analyzes normal transaction of warp finance.

```python
from analyzer.detection_rules import analyze_with_no_abi, analyze_mutate_function_input
print('warp finance attack')
target_tx = '0xc869de9b05b82e370071b4203ef3366dc8a7cdbcb699795af622d5c9d6089072'
analyze_with_no_abi(target_tx)
analyze_mutate_function_input(target_tx)
```
## past attacks
### Warp Finance
* Attack Tx
    * 0x8bb8dc5c7c830bac85fa48acad2505e9300a91c3ff239c9517d0cae33b595090
* Normal Tx (RR)
    * 0xc869de9b05b82e370071b4203ef3366dc8a7cdbcb699795af622d5c9d6089072
* Normal Tx (RT)
    * 0xe16b8eb01f13aa897fb5329401a7ca475fea87addd8e523ceaf2df3d785b5859
### Value Defi Attack
* Attack Tx
    * 0x46a03488247425f845e444b9c10b52ba3c14927c687d38287c0faddc7471150a
* Normal Tx (RR)
    * 0x40967af3e2db0f16ca84c55807cdad2adca03cc07ae5b06e5e61b63ddb2b768c
* Normal Tx (RT)
    * 0xa07d381e9f1ebe49c26735118798449f35975e0baa2bd174a7e3c976583b7e61
### Harvest finance Attack
* Attack Tx
    * 0x35f8d2f572fceaac9288e5d462117850ef2694786992a8c3f6d02612277b0877
* Normal Tx (RT)
    * 0x8076d54315391ca406fa580dbd2f891bc7901ffaf10207aab59cd4138bdd367f
### BZX 2nd attack
* Attack Tx
    * 0x762881b07feb63c436dee38edd4ff1f7a74c33091e534af56c9f7d49b5ecac15
* Normal Tx (RR)
    * 0x442703a4ddbd4f2b80508b44b2456e3f92cfb47d67b441380c8c1ad726ffaa15

### Pluoto
* Attack Tx
    * 0xb4dd46d5d85a1b04fa4af30efaa57fab98ea03ae19de46aaf215706fd120af44
* Normal Tx pluoto (pUSDT) (RT):
    * 0xc75f3722757f1a77a55fce91b7ff82bda26f8ce84e1df77248860bddacd07649
* Normal Tx pluoto (pUSDC) (RT):
    * 0x4728ba55d620fb42641885d15f78ba2f2e907642135a300d2e93e17002a070e8
### Vulnerable contracts mentioned in the paper

* Origin Dollar:
    * 0x503f96f222cde9a114a028e6def163f7449753747f19be29874e2a025f525137
* Crit (cDAI):
    * 0x9fc8b512171f7c3eb8c390d27c457c6a3348e7600863ab8f15389b1f1f7e03be
* Crit (cUSDT)
    * 0x41bc916d0da8d083481cce2e3a79b31a4af1e22d0de6e019bb0d076883c355c9
* Crit (cUSDC)
    * 0x5c987bbd85886202f6c39f078763ed21ea598402ff572504c1748553b7f7317b
* bamVault (bUSDC):
    * 0x3ab0fa8423809a9076e6d5eec21892c22dc50bbeb92c42f809360d0e57ac933f
* bamVault (bDAI):
    * 0xb25ef46b1faf61922fa48ee15b8e008b4bbfc4695418d7c32895d20658808c77
* bamVault (bUSDT):
    * 0x5e1bcb4175d00c2e4b50d3a4824d97d965d31525378b7fba874a10f2c5b354d4
* oneearth (oUSDT):
    * 0xefd910f442940b30b130e2c0b4eff0342ab00537dd8ce8ca11712366873d2791
* oneearth tether USDT:
    * 0x5e1bcb4175d00c2e4b50d3a4824d97d965d31525378b7fba874a10f2c5b354d4
* StrategySwerveUSD:
    * 0x8eef7931a2dc895d400486611dc7ddbbbeec35d9d75fb1670d8cebbd7d5e82b5
* DepositHelper:
    * 0x8eef7931a2dc895d400486611dc7ddbbbeec35d9d75fb1670d8cebbd7d5e82b5
