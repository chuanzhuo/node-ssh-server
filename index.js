var net = require('net');

var Binary = require('binary');
var Put = require('put');

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
}
