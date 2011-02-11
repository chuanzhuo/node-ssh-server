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
        .tap(function (end) {
            var negotiation = this.vars.choices.key_algorithms.serverName;
            if (negotiation === 'diffie-hellman-group1-sha1') {
                // ultimately generate shared secret K and an exchange hash H
                var K = null, H = null;
                var p = 143; // a large safe prime
                
            }
            else {
                console.error('Unsupported negotiation');
            }
        })
    ;
}
