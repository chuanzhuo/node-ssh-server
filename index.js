var net = require('net');
var Binary = require('binary');
var Put = require('put');

var constants = require('./lib/constants');
var keyExchange = require('./lib/kex');
var frame = require('./lib/frame');
var dss = require('./lib/dss');

module.exports = function (opts) {
    var gen = dss.generate(opts.dss);
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
            var algo = vars.choices.kex_algorithms.serverName;
            var neg = keyExchange.negotiations[algo];
            vars.ident = ident;
            
            if (!neg) {
                console.error('Unrecognized negotation algorithm ' + algo);
                stream.end();
            }
            else {
                this
                    .tap(frame.unpack('kexdh'))
                    .tap(function (kvars) {
                        vars.dh = kvars;
                        neg(gen, vars, function (err, reply) {
                            if (err) {
                                console.error(err);
                                stream.end();
                            }
                            else {
                                reply.write(stream);
                            }
                        });
                    })
                ;
            }
        })
    ;
}
