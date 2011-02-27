var Binary = require('binary');
var Put = require('put');
var constants = require('./constants');
var frame = require('./frame');

var bigint = require('bigint');
var crypto = require('crypto');

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
        .word8(0) // first_kex_packet_follows (don't guess)
        .word32be(0) // reserved
    ;
};

exports.select = function (req, algo) {
     return first(req[algo].algorithms, function (name) {
        var cname = name.replace(/-/g,'').replace(/^hmac/,'');
        return first(constants.algorithms, function (x) {
            for (var i = 0; i < x.names.length; i++) {
                var n = x.names[i];
                if (n.replace(/-/g,'') === cname) {
                    return { serverName : n, clientName : name };
                }
            }
        });
    });
};

function first (xs, cb) {
    for (var i = 0; i < xs.length; i++) {
        var res = cb(xs[i], i);
        if (res !== undefined) return res;
    }
    return undefined;
}

exports.response = function (req) {
    var algos = constants.algorithms;
    var choices = [];
    var res = { choices : {} };
    for (var i = 0; i < algos.length; i++) {
        var algo = algos[i].key;
        var choice = exports.select(req, algo);
        choices.push(choice);
        res.choices[algo] = choice;
    }
    res.buffer = exports.pack(
        choices.map(function (c) { return c ? c.clientName : 'none' })
    ).buffer();
    return res;
};

exports.negotiations = {
    'diffie-hellman-group1-sha1' : dh,
};

function dh (gen, vars, cb) {
    var kexdh = vars.dh.kexdh.payload;
    if (kexdh[0] !== constants.magic.kexdh_init) {
        cb('Non-kexdh follows diffie-hellman negotation');
        return;
    }
    
    var e = bigint.fromBuffer(
        Binary.parse(kexdh)
            .skip(1)
            .word32be('length')
            .buffer('e', 'length')
            .vars.e
    );
    
    var session = gen.session();
    
    function spack (buf) {
        return Put().word32be(buf.length).put(buf).buffer();
    }
    
    var f = gen.g.powm(session.y, gen.p);
    var K = e.powm(session.y, gen.p);
    
    var K_S = Put() // K_S
        .put(spack(new Buffer('ssh-dss')))
        .put(gen.p.toBuffer('mpint'))
        .put(gen.q.toBuffer('mpint'))
        .put(session.y.toBuffer('mpint'))
        .buffer()
    ;
    
    var sign = crypto.createSign('DSA');
    
    sign.update(Put() // V_S
        .word32be(vars.client.version.length)
        .put(vars.client.version)
        .buffer()
    );
    
    sign.update(Put() // V_C
        .word32be(vars.ident.length)
        .put(new Buffer(vars.ident))
        .buffer()
    );
    
    sign.update(K_S);
    
    sign.update(Put() // I_C
        .word32be(kexdh.length)
        .put(kexdh)
        .buffer()
    );
    
    sign.update(Put() // I_S
        .word32be(vars.keyxRes.buffer.length)
        .put(vars.keyxRes.buffer)
        .buffer()
    );
    
    sign.update(kexdh.slice(1)) // e
    
    sign.update(f.toBuffer('mpint'));
    sign.update(K.toBuffer('mpint'));
    
    var signed = new Buffer(
        sign.sign(gen.privkey, 'base64'), 'base64'
    );
    
    cb(null, frame.pack(8, Put()
        .word8(constants.magic.kexdh_reply)
        .word32be(K_S.length + f.toBuffer('mpint').length + spack(signed).length)
        .put(K_S)
        .put(f.toBuffer('mpint'))
        .put(spack(signed))
        .buffer()
    ));
    
    console.log(K_S);
    //console.dir(signed);
}
