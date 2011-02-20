var crypto = require('crypto');

var net = require('net');
var Binary = require('binary');
var Put = require('put');
var bigint = require('bigint');

var constants = require('./lib/constants');
var keyExchange = require('./lib/kex');
var frame = require('./lib/frame');
var dss = require('./lib/dss');

module.exports = function (opts) {
    var gen = dss.generate();
    return net.createServer(session.bind({}, gen, opts || {}));
};

function session (gen, opts, stream) {
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
                        var kexdh = kvars.kexdh.payload;
                        if (kexdh[0] !== constants.magic.kexdh_init) {
                            console.error('Non-kexdh follows'
                                + ' diffie-hellman negotation');
                            stream.end();
                        }
                        
                        var e = bigint.fromBuffer(
                            Binary.parse(kexdh)
                                .skip(1)
                                .word32be('length')
                                .buffer('e', 'length')
                                .vars.e
                        );
                        
                        var session = gen.session();
                        
                        function ipack (buf) {
                            return Put().word32be(buf.length).buffer(buf);
                        }
                        
                        var f = gen.g.powm(session.y, gen.p);
                        var fbuf = ipack(f.toBuffer());
                        
                        var K = e.powm(session.y, gen.p);
                        var Kbuf = ipack(K.toBuffer());
                        
                        var K_S = Put() // K_S
                            .word32be(opts.dss.pubkey)
                            .put(new Buffer(opts.dss.pubkey))
                            .buffer()
                        ;
                        
                        var sign = crypto.createSign('DSA');
                        
                        sign.update(Put() // V_S
                            .word32be(vars.client.version.length)
                            .put(vars.client.version)
                            .buffer()
                        );
                        
                        sign.update(Put() // V_C
                            .word32be(ident.length)
                            .put(new Buffer(ident))
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
                        
                        sign.update(fbuf);
                        sign.update(Kbuf);
                        
                        var signed = new Buffer(
                            sign.sign(opts.dss.privkey, 'base64'), 'base64'
                        );
                        
                        Put()
                            .put(K_S)
                            .put(fbuf)
                            .word32be(signed.length)
                            .put(signed)
                            .write(stream)
                        ;
                        
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
