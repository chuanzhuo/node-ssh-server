var net = require('net');

var Binary = require('binary');
var Put = require('put');

var magic = {
    kexinit : 20,
};

var algorithms = [
    {
        key : 'kex_algorithms',
        names : [ 'diffie-hellman-group1-sha1' ],
    },
    {
        key : 'server_host_key_algorithms',
        names : [],
    },
    {
        key : 'encryption_algorithms_client_to_server',
        names : [],
    },
    {
        key : 'encryption_algorithms_server_to_client',
        names : [],
    },
    {
        key : 'mac_algorithms_client_to_server',
        names : [],
    },
    {
        key : 'mac_algorithms_server_to_client',
        names : [],
    },
    {
        key : 'compression_algorithms_client_to_server',
        names : [],
    },
    {
        key : 'compression_algorithms_server_to_client',
        names : [],
    },
    {
        key : 'languages_client_to_server',
        names : [],
    },
    {
        key : 'languages_server_to_client',
        names : [],
    },
];

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
                .word8(magic.kexinit)
                .put(new Buffer(16)) // cookie
                .put(algorithms.reduce(function (put, algo) {
                    return put.put(nameList(algo.names))
                }, Put()).buffer())
            ;
        })
        .word32be('frame.packetLen')
        .word8('frame.paddingLen')
        .tap(function (vars) {
            var frame = vars.frame;
            frame.payloadLen = frame.packetLen - frame.paddingLen - 1;
        })
        .buffer('frame.payload', 'frame.payloadLen')
        .skip('frame.paddingLen')
        .tap(function (vars) {
console.dir(vars.frame.payload.toString());
            var keyx = Binary.parse(vars.frame.payload)
                .word8('kexinit')
                .vars
            ;
console.dir(keyx);
            
            if (keyx.kexinit !== magic.kexinit) {
                console.error('Non-kexinit response');
                stream.end();
            }
            else {
                Put()
                    .word8(0) // first_kex_packet_follows
                    .word32be(0) // reserved
                    .write(stream)
                ;
            }
        })
    ;
    
    stream.end();
}

var frame = exports.frame = function (blockSize, payload, mac) {
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
