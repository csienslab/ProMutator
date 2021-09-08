from .utils import Contract, get_code_from_adr, w3, parse_traces, get_revert_reason
from .decoder import trace_transaction, mutate_call_trace, make_mutate_map
# from mutate import mutate_input

from web3 import Web3
import json
from hexbytes import HexBytes
from web3._utils.events import get_event_data


UNISWAP_V2ROUTER02 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d'
UNISWAP_V2ROUTER01 = '0xf164fc0ec4e93095b804a4795bbe1e041497b92a'

def find_by_sig(traces, signatures, depth=0):
    if traces is None:
        return

    to_adr = traces['to']
    from_adr = traces['from']

    calls = []

    if 'calls' in traces.keys():
        for c in traces['calls']:
            pairs = find_by_sig(c, signatures, depth+1)
            for p in pairs:
                calls.append(p)

    if 'input' in traces.keys():
        if traces['input'][:10] in signatures:
            calls.append({'from': from_adr, 'to': to_adr, 'input': traces['input']})

    return calls

def get_suspicious_fields(fn_tuple):
    threshold = 1000
    try:
        abi = fn_tuple[0].abi
        suspicious_field = []
        for input_field in abi['inputs']:
            if input_field['type'] == 'uint256' or input_field['type'] == 'uint128':
                if fn_tuple[1][input_field['name']] > threshold:
                    suspicious_field.append(input_field['name'])
    except Exception as e:
        # print(e)
        return []
    return suspicious_field


def detection_mutate_input(tx, parsed):
    if parsed['error'] != '':
        return []
    amplified_rates = [1.1, 2, 3, 4]
    suspicious_fields = get_suspicious_fields(parsed['input'])
    if len(suspicious_fields) == 0:
        return []
    
    contract = get_code_from_adr(parsed['to'])._contract
    original_data = parsed['input']
    inputs = []
    for field in suspicious_fields:
        for amplified_rate in amplified_rates:
            tmp = original_data[1]
            tmp[field] = int(tmp[field]*amplified_rate)
            input = contract.encodeABI(original_data[0].fn_name, tmp)

            traces = mutate_call_trace(tx, make_mutate_map([], []), input)
            if 'error' in traces['result'].keys():
                inputs.append((input, field, amplified_rate, tmp))
    
    return inputs
        


def find_getReserves(parsed):
    calls = []
    if 'input' in parsed.keys():
        try:
            if parsed['input'][0].fn_name == 'getReserves' and parsed['from'] != UNISWAP_V2ROUTER01 and parsed['from'] != UNISWAP_V2ROUTER02:
                calls.append({
                    'input': parsed['input'],
                    'from': parsed['from'],
                    'to': parsed['to'],
                })
        except:
            pass
    if 'calls' in parsed.keys():
        for call in parsed['calls']:
            tmp = find_getReserves(call)
            for c in tmp:
                calls.append(c)
    return calls     


def find_fn(parsed, fn_names):
    calls = []
    if 'input' in parsed.keys():
        try:
            if parsed['input'][0].fn_name in fn_names:
                calls.append({
                    'input': [parsed['input'][0].fn_name],
                    'from': parsed['from'],
                    'to': parsed['to'],
                })
        except:
            pass
    if 'calls' in parsed.keys():
        for call in parsed['calls']:
            tmp = find_fn(call, fn_names)
            for c in tmp:
                calls.append(c)
    return calls


def convert_event(event):
    topics = []
    if 'topics' in event.keys():
        for topic in event['topics']:
            topics.append(HexBytes(topic))
        event['topics'] = topics
    if 'data' in event.keys():
        event['data'] = HexBytes(event['data'])
    
    # we dont need these fileds; we just insert useless
    event['blockNumber'] = 0
    event['transactionIndex'] = 0
    event['blockHash'] = HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000')
    event['transactionHash'] = HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000')
    return event


def collect_event(traces, event_type='transfer'):
    erc20_transfer_abi = json.loads('{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"}')
    events = []

    if event_type == 'transfer':
        for event in traces['events']:
            try:
                events.append(get_event_data(w3.codec, erc20_transfer_abi, convert_event(event)))
            except Exception as e:
                # print(e)
                pass
    else:
        raise "unsupported"
    return events


def mutate(tx, calls, rates, normal_transfers, type='callee', mutated_input=''):
    mutate_entrypoints = []
    distinct_adr = []
    for call in calls:
        if type == 'callee' or type  == 'reserves':
            if call['to'] not in distinct_adr:
                distinct_adr.append(call['to'])
                mutate_entrypoints.append((call['to'], call['input'][:10]))
        elif type == 'src':
            if call['input'][1]['src'] not in distinct_adr:
                distinct_adr.append(call['input'][1]['src'])
                mutate_entrypoints.append((call['input'][1]['src'] , 'getExpectedRate'))

    suspicious_dict = []
    is_become_normal = False
    for entrypoint in mutate_entrypoints:
        for rate in rates:
            print("mutating {} : {} rate: {}".format(entrypoint[1], entrypoint[0], rate))
            traces = mutate_call_trace(tx, make_mutate_map([entrypoint[0]], [rate]), mutated_input)

            if type == 'reserves':
                if not 'error' in traces['result'].keys():
                    suspicious_dict.append({
                        'tx': tx,
                        'rate': rate,
                        'type': entrypoint[1],
                        'entrypoint': entrypoint[0],
                        'suspicious': {
                            'type': 'normal',
                        }
                    })
                    is_become_normal = True

            suspicious = detection_compare_revert_and_transfers(normal_transfers, traces['result'])
            if  len(suspicious) > 0:
                suspicious_dict.append({
                    'tx': tx,
                    'rate': rate,
                    'type': entrypoint[1],
                    'entrypoint': entrypoint[0],
                    'suspicious': suspicious,
                })

    if type == 'reserves' and not is_become_normal:
        return []
    return suspicious_dict


def detection_compare_revert_and_transfers(normal_transfers, traces):
    if 'error' in traces.keys():
        errorMsg = None
        if 'output' in traces.keys():
            errorMsg = get_revert_reason(traces['output'])
        return {
                'type': 'reverted',
                'msg': errorMsg
            }

    transfers = collect_event(traces)
    if len(transfers) != len(normal_transfers):
        return {
            'type': 'different_transfers',
            'msg': 'normal traces has {} transfers; mutated traces has {} transfers'.format(
            len(normal_transfers), len(transfers))
        }

    inconsists = []
    
    for i in range(len(normal_transfers)):
        normal = normal_transfers[i]
        mutated = transfers[i]

        if normal['address'] != mutated['address']:
            inconsists.append('source address inconsists at log Index: {}\n normal: {}, mutated: {}'.format(
                i, normal['address'], mutated['address']))
            continue

        if normal['args']['from'] != mutated['args']['from']:
            inconsists.append('from address inconsists at log Index: {}\n normal: {}, mutated: {}'.format(
                i, normal['args']['from'], mutated['args']['from']))
        
        if normal['args']['to'] != mutated['args']['to']:
            inconsists.append('to address inconsists at log Index: {}\n normal: {}, mutated: {}'.format(
                i, normal['args']['to'], mutated['args']['to']))
        
        if normal['args']['value'] != mutated['args']['value']:
            inconsists.append('Transfer value inconsists at log Index: {}\n normal: {}, mutated: {}'.format(
                i, normal['args']['value'], mutated['args']['value'])) 
    if len(inconsists) == 0:
        return {}
    return {
        'type': 'value-inconsists',
        'msg': json.dumps(inconsists),
        'mutatedTransfers': Web3.toJSON(transfers),
    }


skip_address_list = [
    # '0xf8ce90c2710713552fb564869694b2505bfc0846', # farm_depositer
    # '0xc7ee21406bb581e741fbb8b21f213188433d9f2f', # farm fusd
    # '0xfbe122d0ba3c75e1f7c80bd27613c9f35b81feec', # farm renBTC
    # '0xc391d1b08c1403313b0c28d47202dfda015633c4', # farm renBTC
    # '0xc3f7ffb5d5869b3ade9448d094d81b0521e8326f', # farm fusdc
    # '0xe85c8581e60d7cd32bbfd86303d2a4fa6a951dac', # farm fdai
    # '0xc07eb91961662d275e2d285bdc21885a4db136b0', # farm wbtc
    # '0x5d9d25c7c457dd82fc8668ffc6b9746b674d4ecb', # farm wbtc
    # '0x7674622c63bee7f46e86a4a5a18976693d54441b', # farm tusd
    # '0xab7fa2b2985bccfc13c6d86b1d5a17486ab1e04c', # farm fdai
    # '0xf0358e8c3cd5fa238a29301d0bea3d63a17bedbe', # farm usdc
    # '0x053c80ea73dc6941f518a68e2fc52ac45bde7c9c', # farm usdt
    # '0xf8ce90c2710713552fb564869694b2505bfc0846', # harvest deposit helper
    # '0x222412af183bceadefd72e4cb1b71f1889953b1c', # harvest controller

    # '0x751be7ddeccb9ece9dd29eafee8a53d3d7d5e0c4', # plouto
    # '0xa385f753baaae6e1d8c16fd03e069b04df624258', # plouto

    # '0x73ab2bd10ad10f7174a1ad5afae3ce3d991c5047', # crv router


    # '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', # 


    # skips for performance
    '0x11111254369792b2ca5d084ab5eea397ca8fa48b', # 1inch 
    '0x1c47343ea7135c2ba3b2d24202ad960adafaa81c', # aave too heavy
    '0x78a55b9b3bbeffb36a43d9905f654d2769dc55e8', # arbitrage bot

    # harvest attackers
    '0xc6028a9fa486f52efd2b95b949ac630d287ce0af',

    #known bot
    '0xbc7a3b935869fe86f14da5187c4cf467b8ee7bdd',
    #known price feed
    '0x290c2df684d9dc7bd094061e5bbb562d49e6bbc5',
]
YELLOW_ASCII = '\033[93m'
GREEN_ASCII = '\033[92m'
RED_ASCII = '\033[91m'

def get_code_input(tx_hash):
    tx = w3.eth.getTransaction(tx_hash)
    c = get_code_from_adr(tx['to'])
    return c.decode_input(tx['input'])

def analyze_mutate_function_input(tx, log=None, detail=False):
    # first collect normal trace
    print(YELLOW_ASCII, 'start anaylzing tx:', tx)

    ## check is there a suspicious fields. return if not
    try:
        fn_tuple = get_code_input(tx)
        if len(get_suspicious_fields(fn_tuple)) == 0:
            print('no sus')
            return
    except Exception as e:
        # print(e)
        return
    traces = trace_transaction(tx)
    try:
        traces = traces['result']
    except:
        print(traces)
        return

    if 'error' in traces.keys() or traces['to'] in skip_address_list:
        print(YELLOW_ASCII, 'skip tx..')
        return
    else:
        print('entry point:', traces['to'])
    transfers = collect_event(traces, 'transfer')
    # collect
    print('collects {} transfers events'.format(len(transfers)))

    print('decoding traces')
    p_traces = parse_traces(traces)

    calls = find_fn(p_traces, ["getReserves", "getExpectedRate", "calc_token_amount", "calc_withdraw_one_coin"])

    # calls = find_getReserves(parsed_traces)

    mutated_inputs = detection_mutate_input(tx, p_traces)

    detail_output = []
    for input in mutated_inputs:
        print('mutated suspicious field', input[1], 'rate', input[2])
        suspicious = mutate(tx, calls,
            [1.1, 0.9, 1.5, 0.75, 2, 0.5, 5, 0.2, 10, 0.1, 100, 0.01],
            transfers, 'reserves', input[0]
            )
        if  len(suspicious) > 0:
            if log is not None:
                for s in suspicious:
                    log(s)
                    print(RED_ASCII, s)
            if detail:
                detail_output.append({
                    'mutateField': input[1],
                    'mutatedArgs': input[3],
                    'mutateRate': input[2],
                    'mutatedInputValue': input[0],
                    'suspicious': suspicious
                })

    if detail:
        return {
            'normalTransfers': Web3.toJSON(transfers),
            'detailOutput': detail_output
        }

def analyze_with_no_abi(tx, log=None, detail=False):
    # first collect normal trace
    print(YELLOW_ASCII, 'start anaylzing tx:', tx)
    traces = trace_transaction(tx)
    try:
        traces = traces['result']
    except:
        print(traces)
        return

    if 'error' in traces.keys(): # or traces['to']: # in skip_address_list:
        print(YELLOW_ASCII, 'skip tx..')
        return
    else:
        print('entry point:', traces['to'])
    transfers = collect_event(traces, 'transfer')
    # collect
    print('collects {} transfers events'.format(len(transfers)))

    # parsed_traces = parse_traces(traces)

    # "3883e119", // calc_token_amount(uint256[3] amounts,bool deposit )
    # "cf701ff7", // calc_token_amount(uint256[4] amounts,bool deposit )
    # "ed8e84f3", // calc_token_amount(uint256[2] amounts,bool deposit )
    # "cc2b27d7", // calc_withdraw_one_coin(uint256 _token_amount,int128 i )
    # "c532a774", // calc_withdraw_one_coin(uint256 _token_amount,int128 i,bool _use_underlying )
    # "41b028f3", // calc_withdraw_one_coin(address _pool,uint256 _token_amount,int128 i )
    # "809a9e55" ,// getExpectedRate(address, address, uint256)

    detail_output = []

    calls = find_by_sig(traces, [
            '0x0902f1ac',
            '0x3883e119', '0xcf701ff7', '0xed8e84f3',
            '0xcc2b27d7', '0xc532a774', '0x41b028f3',
            '0x809a9e55',
        ])
    # calls = find_fn(parsed_traces, ['calc_withdraw_one_coin', 'calc_token_amount'])
    suspicious = mutate(tx, calls, 
        [1.01, 0.99, 2, 0.5, 5, 0.2],
        transfers
        )
    if  len(suspicious) > 0:
        if log is not None:
            for s in suspicious:
                log(s)
                print(RED_ASCII, s)
        if detail:
            detail_output.append({
                'suspicious': suspicious
            })
    if detail:
        return {
            'normalTransfers': Web3.toJSON(transfers),
            'detailOutput': detail_output,
        }
