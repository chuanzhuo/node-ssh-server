var net = require('net');
var Binary = require('binary');
var Put = require('put');

var constants = require('./lib/constants');
var keyExchange = require('./lib/kex');
var frame = require('./lib/frame');

var keyx = require('keyx');

module.exports = function (opts) {
    return net.createServer(function (stream) {
        session(opts || {}, stream)
    });
};

function session (opts, stream) {
    var ident = new Buffer('SSH-2.0-' + (opts.serverName || 'node-ssh-server'));
    Put().put(ident).put(new Buffer('\r\n')).write(stream);
    
    var keypair = keyx(opts);
    
    Binary(stream)
        .scan('client.ident', '\r\n')
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
                
                vars.challenge = {
                    client : {
                        ident : vars.client.ident,
                        kexinit : keyxReq.buffer,
                    },
                    server : {
                        ident : ident,
                        kexinit : keyxRes.buffer,
                    },
                };
            }
        })
        .tap(function (vars) {
            var algo = vars.choices.kex_algorithms.serverName;
            this
                .tap(frame.unpack('kexdh'))
                .tap(function (kvars) {
                    var kexdh = kvars.kexdh.payload;
                    var challenge = vars.challenge;
                    var buf = keypair.challenge(algo, kexdh, challenge);
                    frame.pack(8, buf).write(stream);
console.log('--- challenged ---');
console.log(buf);
                })
                .word32be('service.length')
                .buffer('service.buffer')
                .tap(function (kvars) {
console.log('service');
console.dir(kvars.service);
                })
            ;
        })
    ;
}
