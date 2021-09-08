from analyzer.utils import w3
# from analyzer.decoder import trace_transaction
import json
with open('./extracter.js', 'r') as f:
    extracter = f.read()

import os
import sys

# start_block = 9932782
# end_block = start_block + 2000
start_block = int(sys.argv[1])
end_block = int(sys.argv[2])


TX_LOG_PATH = './target_tx_dup.csv'
if not os.path.exists(TX_LOG_PATH):
    with open(TX_LOG_PATH, 'w') as f:
        f.write("block_num,tx_index,tx_hash,entrypoint,signatures\n")

def log_tx(blocknum, txindex, entrypoint, signatures):
    block = w3.eth.getBlock(blocknum)
    with open(TX_LOG_PATH, 'a') as f:
        f.write("{},{},{},{},\"{}\"\n".format(
            blocknum,
            txindex,
            block['transactions'][txindex].hex(),
            str(entrypoint),
            json.dumps(signatures).replace('"', "'")
            ))




for i in range(start_block, end_block):
    print("scanning ", i)
    blocks = w3.provider.make_request("debug_traceBlockByNumber", [hex(i), {'tracer': extracter}])
    if 'result' not in blocks:
        print(blocks)
        continue
    for j in range(len(blocks['result'])):
        if 'result' not in blocks['result'][j]:
            print(blocks['result'][j])
            continue
        b = blocks['result'][j]['result']
        if 'signatures' in b.keys() and len(b['signatures']) > 0:
            log_tx(i, j, b['entrypoint'], b['signatures'])



