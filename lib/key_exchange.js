var Binary = require('binary');
var Put = require('put');
var constants = require('./constants');

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

exports.pack = function (selected) {
    return Put()
        .word8(constants.magic.kexinit)
        .put(new Buffer(16)) // cookie
        .put(selected.reduce(function (put, algo) {
            var buf = new Buffer(algo);
            return put.word32be(buf.length).put(buf);
        }, Put()).buffer())
        .word8(0) // first_kex_packet_follows
        .word32be(0) // reserved
    ;
};

exports.select = function (req, algo) {
     return detect(req[algo].algorithms, function (name) {
        var cname = name.replace(/-/g,'');
        return detect(constants.algorithms, function (x) {
            return x.names.map(function (n) {
                return n.replace(/-/g,'')
            }).indexOf(cname);
        });
    });
};

exports.response = function (req) {
    var algos = constants.algorithms;
    var choices = [];
    for (var i = 0; i < algos.length; i++) {
        var algo = algos[i].key;
        var choice = exports.select(req, algo);
        if (!choice && !algo.match(/^languages_/)) {
            console.error('No compatible algorithm for ' + algo);
            return undefined;
        }
        choices.push(choice || '');
    }
    return exports.pack(choices);
};

function detect (xs, cb) {
    for (var i = 0; i < xs.length; i++) {
        if (cb(xs[i], i)) return xs[i];
    }
    return undefined;
}
