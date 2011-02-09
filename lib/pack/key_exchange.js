var Binary = require('binary');
var Put = require('put');
var constants = require('../constants');

exports.unpack = function (buf) {
    var algos = constants.algorithms.slice();
    
    var keyx = Binary.parse(buf)
        .word8('kexinit')
        .buffer('cookie', 16)
        .loop(function (end) {
            var algo = algos.shift();
            if (!algo) end()
            else {
                this
                    .word32be(algo.key + '.size')
                    .buffer(algo.key + '.buffer', algo.key + '.size')
                    .tap(function (vars) {
                        vars[algo.key].algorithms = 
                            vars[algo.key].buffer.toString().split(',');
                    })
                ;
            }
        })
        .word8('first_kex_packet_follows')
        .word32be('reserved')
        .vars
    ;
    
    return keyx.kexinit === constants.magic.kexinit
        ? keyx : undefined
    ;
};

exports.pack = function (algos) {
    return Put()
        .word8(constants.magic.kexinit)
        .put(new Buffer(16)) // cookie
        .put(algos.reduce(function (put, algo) {
            var names = new Buffer(algo.names.join(','));
            return put.word32be(names.length).put(names);
        }, Put()).buffer())
        .word8(0) // first_kex_packet_follows
        .word32be(0) // reserved
    ;
};
