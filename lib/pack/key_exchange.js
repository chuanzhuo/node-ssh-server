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
        .vars
    ;
    
    return keyx.kexinit === constants.magic.kexinit
        ? keyx : undefined
    ;
};

exports.pack = function (algos) {
    function nameList (xs) {
        var names = new Buffer((xs || []).join(','));
        return Put().word32be(names.length).put(names).buffer();
    }
    
    return Put()
        .word8(constants.magic.kexinit)
        .put(new Buffer(16)) // cookie
        .put(algos.reduce(function (put, algo) {
            return put.put(nameList(algo.names))
        }, Put()).buffer())
    ;
};
