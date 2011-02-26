var bigint = require('bigint');
var assert = require('assert');

// Generate two primes p and q to the Digital Signature Standard (DSS)
// http://www.itl.nist.gov/fipspubs/fip186.htm appendix 2.2

exports.generate = function (keys) {
    var q = bigint(2).pow(159).add(1).rand(bigint(2).pow(160)).nextPrime();
    var L = 512 + 64 * Math.floor(Math.random() * 8);
    
    do {
        var X = bigint(2).pow(L-1).add(1).rand(bigint(2).pow(L));
        var c = X.mod(q.mul(2));
        var p = X.sub(c.sub(1)); // p is congruent to 1 % 2q somehow!
    } while (p.lt(bigint.pow(2, L - 1)) || p.probPrime(50) === false)
    
    assert.ok(q.gt(bigint.pow(2,159)), 'q > 2**159');
    assert.ok(q.lt(bigint.pow(2,160)), 'q < 2**160');
    assert.ok(p.gt(bigint.pow(2,L-1)), 'p > 2**(L-1)');
    assert.ok(q.lt(bigint.pow(2,L)), 'p < 2**L');
    assert.ok(q.mul(p.sub(1).div(q)).add(1).eq(p), 'q divides p - 1');
    
    do {
        var e = p.sub(1).div(q);
        var h = p.sub(2).rand().add(1);
        var g = h.powm(e, p);
    } while (g.eq(1))
    
    return {
        // p, q, and g can be shared and re-used
        p : p, q : q, g : g,
        pubkey : keys.pubkey,
        privkey : keys.privkey,
        
        session : function () {
            var x = q.sub(1).rand().add(1); // private key
            var y = g.powm(x, p); // public key
            
            return {
                x : x, y : y,
                k : function () { // regenerate for each signature
                    return q.sub(1).rand(x).add(1);
                },
            };
        },
    };
};
