
from .utils import w3

callTracer = ''
with open('./callTracer.js', 'r') as f:
    callTracer = f.read()
    f.close()

import json


def make_mutate_map(addresses, rates):
    mutate_maps = []
    for i in range(len(addresses)):
        mutate_maps.append({
            'address': addresses[i],
            'mutateRate': '{}'.format(rates[i])
        })
    return mutate_maps


def trace_event_by_tx_hash(hash):
    return w3.provider.make_request('debug_traceTransaction', [
        hash, {'tracer': 'callTracer', 'timeout': '1000000s'}
    ])

def mutate_event(hash):
    return w3.provider.make_request('debug_mutateTraceTransaction', [
        hash,
        {},
        make_mutate_map(['0xbb2b8038a1640196fbe3e38816f3e67cba72d940'], [10000]),
        ''
    ])



def mutate_call_trace(tx_hash, mutate_map, input=''):
    return w3.provider.make_request('debug_mutateTraceTransaction', [
        tx_hash, {
            'tracer': callTracer,
            'timeout': '60000s',
        },
        mutate_map, input
    ])



def trace_transaction(tx):
    return w3.provider.make_request('debug_traceTransaction', [
        tx,
        {
            'tracer': callTracer,
            'timeout': '60000s'
        }
    ])

