// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.


// callTracer is a full blown transaction tracer that extracts and reports all
// the internal calls made by a transaction, along with any useful information.


{
    entrypoint: undefined,
    events: [],
    // callstack is the current recursive call stack of the EVM execution.
    callstack: [{}],

        // descended tracks whether we've just descended from an outer transaction into
        // an inner call.
    descended: false,
    signatures: [],
    targetSignatures: [
        "3883e119", // calc_token_amount(uint256[3] amounts,bool deposit )
        "cf701ff7", // calc_token_amount(uint256[4] amounts,bool deposit )
        "ed8e84f3", // calc_token_amount(uint256[2] amounts,bool deposit )
        "cc2b27d7", // calc_withdraw_one_coin(uint256 _token_amount,int128 i )
        "c532a774", // calc_withdraw_one_coin(uint256 _token_amount,int128 i,bool _use_underlying )
        "41b028f3", // calc_withdraw_one_coin(address _pool,uint256 _token_amount,int128 i )
        "0902f1ac", // getReserves()
        "809a9e55" ,// getExpectedRate(address, address, uint256)
        "cd7724c3", // getEthToTokenInputPrice(uint256)	
	    "59e94862", // getEthToTokenOutputPrice(uint256)
	    "95b68fe7", // getTokenToEthInputPrice(uint256)	    95b68fe7
        "2640f62c",    // getTokenToEthOutputPrice(uint256)    2640f62c    ],
    ],
    targetSignautresFind: [
        false, false, false, false, false, false, false, false,
    ],

    checkAndLog: function(input, caller, callee) {
        
        // return this.signatures.push(typeof this.targetSignatures);
        if (input.length >= 10) {
            var sig = input.slice(2, 10);

            for (var i = 0; i < this.targetSignatures.length; i++) {
                if (sig == this.targetSignatures[i]) {
                    this.targetSignautresFind[i] = true;
                }
            }
            // this.signatures.push(sig);
        }
    },
    // step is invoked for every opcode that the VM executes.
    step: function(log, db) {
        // Capture any errors immediately
        var error = log.getError();
        if (error !== undefined) {
            this.fault(log, db);
            return;
        }
        var op = log.op.toString();
        var syscall = (log.op.toNumber() & 0xf0) == 0xf0;

        // If a new contract is being created, add to the call stack
        if (syscall && (op == 'CREATE' || op == "CREATE2")) {
            var inOff = log.stack.peek(1).valueOf();
            var inEnd = inOff + log.stack.peek(2).valueOf();
            var from = toHex(log.contract.getAddress());
            var input = toHex(log.memory.slice(inOff, inEnd));
            this.checkAndLog(input, from, from);
            return;
        }

        // If a new method invocation is being done, add to the call stack
        if (syscall && (op == 'CALL' || op == 'CALLCODE' || op == 'DELEGATECALL' || op == 'STATICCALL')) {
            // Skip any pre-compile invocations, those are just fancy opcodes
            var to = toAddress(log.stack.peek(1).toString(16));
            if (isPrecompiled(to)) {
                return
            }
            var off = (op == 'DELEGATECALL' || op == 'STATICCALL' ? 0 : 1);
            var inOff = log.stack.peek(2 + off).valueOf();
            var inEnd = inOff + log.stack.peek(3 + off).valueOf();
            var from = toHex(log.contract.getAddress());
            to = toHex(to);
            var input = toHex(log.memory.slice(inOff, inEnd));
            this.checkAndLog(input, from, to);
            return;
        }
    },

    // fault is invoked when the actual execution of an opcode fails.
    fault: function(log, db) {
        // If the topmost call already reverted, don't handle the additional fault again
        if (this.callstack[this.callstack.length - 1].error !== undefined) {
            return;
        }
        // Pop off the just failed call
        var call = this.callstack.pop();
        call.error = log.getError();

        // Consume all available gas and clean any leftovers
        if (call.gas !== undefined) {
            call.gas = '0x' + bigInt(call.gas).toString(16);
            call.gasUsed = call.gas
        }
        delete call.gasIn; delete call.gasCost;
        delete call.outOff; delete call.outLen;

        // Flatten the failed call into its parent
        var left = this.callstack.length;
        if (left > 0) {
            if (this.callstack[left - 1].calls === undefined) {
                this.callstack[left - 1].calls = [];
            }
            this.callstack[left - 1].calls.push(call);
            return;
        }
        // Last call failed too, leave it in the stack
        this.callstack.push(call);
    },

    // result is invoked when all the opcodes have been iterated over and returns
    // the final result of the tracing.
    result: function(ctx, db) {
        var signatures = [];
        for (var i = 0; i < this.targetSignautresFind.length; i++) {
            if (this.targetSignautresFind[i] === true ) {
                signatures.push(this.targetSignatures[i]);
            }
        }
        return {
            // global: this.signatures,
            signatures: signatures,
            entrypoint: toHex(ctx.to),
        };
    },

    // finalize recreates a call object using the final desired field oder for json
    // serialization. This is a nicety feature to pass meaningfully ordered results
    // to users who don't interpret it, just display it.
    finalize: function(call) {
        var sorted = {
            type: call.type,
            from: call.from,
            to: call.to,
            value: call.value,
            gas: call.gas,
            gasUsed: call.gasUsed,
            input: call.input,
            output: call.output,
            error: call.error,
            time: call.time,
            calls: call.calls,
            events: call.events,
        }
        for (var key in sorted) {
            if (sorted[key] === undefined) {
                delete sorted[key];
            }
        }
        if (sorted.calls !== undefined) {
            for (var i = 0; i < sorted.calls.length; i++) {
                sorted.calls[i] = this.finalize(sorted.calls[i]);
            }
        }
        return sorted;
    }
}
