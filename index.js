var net = require('net');
var Binary = require('binary');
var Put = require('put');

var constants = require('./lib/constants');
var pack = require('./lib/pack');

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
        .tap(pack.frame.unpack('keyframe'))
        .tap(function (vars) {
            var keyxReq = pack.keyExchange.unpack(vars.keyframe.payload);
            var keyxRes = pack.keyExchange
                .pack(constants.algorithms)
                .buffer()
            ;
            
            if (!keyxReq) {
                console.error('Key exchange failed');
                stream.end();
            }
            else {
console.dir(keyxReq);
console.dir(keyxRes);
                pack.frame.pack(8, Put()
                    .put(keyxRes)
                    .buffer()
                ).write(stream);
            }
        })
    ;
}
