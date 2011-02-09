var Put = require('put');

exports.pack = function (blockSize, payload, mac) {
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

exports.unpack = function (name) {
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
