var crypto = require('crypto');

var net = require('net');
var Binary = require('binary');
var Put = require('put');
var bigint = require('bigint');

var constants = require('./lib/constants');
var keyExchange = require('./lib/kex');
var frame = require('./lib/frame');

module.exports = function (opts) {
    return net.createServer(session.bind({}, opts || {}));
};

function session (opts, stream) {
    var ident = 'SSH-2.0-' + (opts.serverName || 'node-ssh-server');
    Put().put(new Buffer(ident + '\r\n')).write(stream);
    
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
                vars.keyxRes = keyxRes;
            }
        })
        .tap(function (vars) {
            var negotiation = vars.choices.kex_algorithms.serverName;
            if (negotiation === 'diffie-hellman-group1-sha1') {
                
                this
                    .tap(frame.unpack('kexdh'))
                    .tap(function (kvars) {
console.dir(kvars.kexdh);
                        var kexdh = kvars.kexdh.payload;
                        if (kexdh[0] !== constants.magic.kexdh_init) {
                            console.error('Non-kexdh follows'
                                + ' diffie-hellman negotation');
                            stream.end();
                        }
                        
                        var e = bigint.pack(
                            Binary.parse(kexdh)
                                .skip(1)
                                .word32be('length')
                                .buffer('e', 'length')
                                .vars.e
                        );
                        var sign = crypto.createSign('DSA');
                        sign.update(vars.client.version); // V_S
                        sign.update(ident); // V_C
                        sign.update(opts.dss.pubkey); // K_S
                        sign.update(kexdh); // I_C
                        sign.update(vars.keyxRes.buffer); // I_S
                        var signed = new Buffer(
                            sign.sign(opts.dss.privkey, 'base64'),
                            'base64'
                        );
                        
                        console.dir(signed);
                    })
                ;
            }
            else {
                console.error('Unsupported negotiation');
            }
        })
    ;
}
