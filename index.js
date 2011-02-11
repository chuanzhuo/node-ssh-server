var net = require('net');
var Binary = require('binary');
var Put = require('put');
var Hash = require('hashish');

var constants = require('./lib/constants');
var keyExchange = require('./lib/kex');
var frame = require('./lib/frame');

module.exports = function (opts) {
    return net.createServer(session.bind({}, opts || {}));
};

function session (opts, stream) {
    Put()
        .put(new Buffer(
            'SSH-2.0-' + (opts.serverName || 'node-ssh-server') + '\r\n'
        ))
        .write(stream)
    ;
    
    Binary(stream)
        .scan('client.version', '\r\n')
        .tap(frame.unpack('keyframe'))
        .tap(function (vars) {
            var keyxReq = keyExchange.unpack(vars.keyframe.payload);
            var keyxRes = keyExchange.response(keyxReq);
            
            if (!keyxReq) {
                console.error('Failed to parse client key exchange');
                stream.end();
            }
            else if (!keyxRes) {
                console.error('Key exchange algorithm selection failed');
                stream.end();
            }
            else {
                frame.pack(8, keyxRes.buffer).write(stream);
                vars.choices = keyxRes.choices;
            }
        })
        .tap(function (vars) {
            var negotiation = vars.choices.kex_algorithms.serverName;
            if (negotiation === 'diffie-hellman-group1-sha1') {
                // ultimately generate shared secret K and an exchange hash H
                var K = null, H = null;
                var p = 331; // a large safe prime
                
                // generator for a subgroup of GF(p)
                // meaning: select an element from [1..p-1], inclusive
                var g = Math.ceil(Math.random() * (p - 1));
                
                // find the order of g, q, such that g**q == 1
                console.log('Computing...');
                var gq = g;
                for (var q = 1; gq % p !== 1; q++) {
                    gq = (gq * g) % p;
                }
                console.dir([ q, gq ]);
                
                var y = Math.ceil(Math.random() * (q - 1));
                
                this
                    .word8('kexdh')
                    .tap(function (vars) {
console.log(vars.kexdh);
                        if (vars.kexdh !== constants.magic.kexdh_init) {
                            console.error('Non-kexdh follows'
                                + ' diffie-hellman negotation');
                            stream.end();
                        }
                    })
                    .word32be('e.length')
                    .buffer('e.buffer', 'e.length')
                    .tap(function (vars) {
                        K = Math.pow(e, y) % p;
                        console.dir({ K : K });
                    })
                ;
            }
            else {
                console.error('Unsupported negotiation');
            }
        })
    ;
}
