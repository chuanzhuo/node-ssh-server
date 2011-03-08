var fs = require('fs');
var ssh = require('ssh-server');
var keyx = require('keyx');
var argv = require('optimist')
    .demand([ 'pub', 'priv' ])
    .demand(1)
    .usage('$0 ( generate | listen ) --pub=KEY.pub --priv=KEY.priv')
    .argv
;

var cmd = argv._.shift();
if (cmd === 'generate') {
    console.log('Generating key pair...');
    var keypair = keyx.generate('dss');
    var format = argv.format || 'ssh2';
    console.log('Writing to disk in ' + format + ' format');
    fs.writeFileSync(
        argv.priv,
        keypair.key('priv').format(format || 'ssh2')
    );
    fs.writeFileSync(
        argv.pub,
        keypair.key('pub').format(format || 'ssh2')
    );
    console.log('Done.');
}
else if (cmd === 'listen') {
    ssh({
        pub : fs.readFileSync(argv.pub),
        priv : fs.readFileSync(argv.priv),
    }).listen(argv.port || 22);
}
else {
    console.error('Unknown command: ' + cmd);
}
