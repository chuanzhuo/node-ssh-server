var Put = require('put');
var crypto = require('crypto');

exports.pack = function (blockSize, payload, mac) {
    var knownLen = 4 + 1 + payload.length;
    var padLen = blockSize - (knownLen % blockSize);
    if (padLen < 4) padLen += blockSize;
    
    var packetLen = 1 + payload.length + padLen;
    
    var packet = Put()
        .word32be(packetLen)
        .word8(padLen)
        .put(payload)
        .put(new Buffer(padLen))
    ;
    return packet.put(mac && mac(packet.buffer()) || new Buffer(0));
};

exports.unpack = function (name, macLen) {
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
            .skip(macLen || 0)
        ;
    };
};
