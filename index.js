var net = require('net');

var Binary = require('binary');
var Put = require('put');

var constants = require('./lib/constants');

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
        .tap(frame.unpack('keyframe'))
        .tap(function (vars) {
            var algos = constants.algorithms.slice();
            var keyx = Binary.parse(vars.keyframe.payload)
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
            
            if (keyx.kexinit !== constants.magic.kexinit) {
                console.error('Non-kexinit response');
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

var frame = exports.frame = {};

frame.pack = function (blockSize, payload, mac) {
    var knownLen = 4 + 1 + payload.length;
    var padLen = blockSize - (knownLen % blockSize);
    if (padLen < 4) padLen += blockSize;
    
    var packetLen = 1 + payload.length + padLen;
    
    return Put()
        .word32be(packetLen)
        .word8(paddingLen)
        .put(payload)
        .put(new Buffer(padLen))
        .put(mac)
        .buffer()
    ;
};

frame.unpack = function (name) {
    return function (vs) {
        this
            .word32be(name + '.packetLen')
            .word8(name + '.paddingLen')
            .tap(function (vars) {
                var x = vars[name];
                x.payloadLen = x.packetLen - x.paddingLen - 1;
            })
            .buffer(name + '.payload', name + '.payloadLen')
            .skip(name + '.paddingLen')
        ;
    };
};
