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
    
    function nameList (xs) {
        var names = new Buffer((xs || []).join(','));
        return Put().word32be(names.length).put(names).buffer();
    }
    
    Binary(stream)
        .scan('client.version', '\r\n')
        .tap(function (vars) {
            Put()
                .word8(constants.magic.kexinit)
                .put(new Buffer(16)) // cookie
                .put(constants.algorithms.reduce(function (put, algo) {
                    return put.put(nameList(algo.names))
                }, Put()).buffer())
            ;
        })
        .tap(pack.frame.unpack('keyframe'))
        .tap(function (vars) {
            var algos = constants.algorithms.slice();
            var keyx = pack.keyExchange.unpack(vars.keyframe.payload);
            
            if (!keyx) {
                console.error('Key exchange failed');
                stream.end();
            }
            else {
console.dir(keyx);
                Put()
                    .word8(0) // first_kex_packet_follows
                    .word32be(0) // reserved
                    //.write(stream)
                ;
            }
        })
    ;
    
    stream.end();
}
