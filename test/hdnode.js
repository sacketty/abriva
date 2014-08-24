var assert = require('assert')
var networks = require('../lib/networks')

var BigInteger = require('bigi')
var HDNode = require('../lib/eccrypto/hdnode')

var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var fixtures = require('./fixtures/hdnode.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('HDNode', function() {
  describe('Constructor', function() {
    var d = BigInteger.ONE
    var Q = curve.G.multiply(d)
    var chainCode = new Buffer(32)
    chainCode.fill(1)

    it('calculates the publicKey from a BigInteger', function(done) {
      var hd = new HDNode(d, chainCode)

      assert(hd.pubKey.Q.equals(Q));
      done();
    })

    it('only uses compressed points', function(done) {
      var hd = new HDNode(Q, chainCode);
      var hdP = new HDNode(d, chainCode);

      assert.strictEqual(hd.pubKey.compressed, true);
      assert.strictEqual(hdP.pubKey.compressed, true);
      done();
    })

    it('has a default depth/index of 0', function(done) {
      var hd = new HDNode(Q, chainCode)

      assert.strictEqual(hd.depth, 0)
      assert.strictEqual(hd.index, 0);
      done();
    })

    it('defaults to the bitcoin network', function(done) {
      var hd = new HDNode(Q, chainCode)

      assert.equal(hd.network, networks.bitcoin);
      done();
    })

    it('supports alternative networks', function(done) {
      var hd = new HDNode(Q, chainCode, networks.testnet)

      assert.equal(hd.network, networks.testnet);
      done();
    })

    it('throws when an invalid length chain code is given', function(done) {
      assert.throws(function() {
        new HDNode(d, chainCode.slice(0, 20), networks.testnet)
      }, /Expected chainCode length of 32, got 20/);
      done();
    })

    it('throws when an unknown network is given', function(done) {
      assert.throws(function() {
        new HDNode(d, chainCode, {})
      }, /Unknown BIP32 constants for network/);
      done();
    })
  })

  describe('fromSeed*', function() {
    fixtures.valid.forEach(function(f) {
      it('calculates privKey and chainCode for ' + f.master.fingerprint, function(done) {
        var hd = HDNode.fromSeedHex(f.master.seed)

        assert.equal(hd.privKey.toWIF(), f.master.wif);
        assert.equal(hd.chainCode.toString('hex'), f.master.chainCode);
        done();
      })
    })

    it('throws on low entropy seed', function(done) {
      assert.throws(function() {
        HDNode.fromSeedHex('ffffffffff')
      }, /Seed should be at least 128 bits/);
      done();
    })

    it('throws on too high entropy seed', function(done) {
      assert.throws(function(done) {
        HDNode.fromSeedHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
      }, /Seed should be at most 512 bits/);
      done();
    })
  })

  describe('toBase58', function() {
    fixtures.valid.forEach(function(f) {
      it('exports ' + f.master.base58 + ' (public) correctly', function(done) {
        var hd = HDNode.fromSeedHex(f.master.seed).neutered()

        assert.equal(hd.toBase58(), f.master.base58);
        done();
      })
    })

    fixtures.valid.forEach(function(f) {
      it('exports ' + f.master.base58Priv + ' (private) correctly', function(done) {
        var hd = HDNode.fromSeedHex(f.master.seed)

        assert.equal(hd.toBase58(), f.master.base58Priv);
        done();
      })
    })

    // FIXME: remove in 2.x.y
    it('fails when there is no private key', function(done) {
      var hd = HDNode.fromBase58(fixtures.valid[0].master.base58)

      assert.throws(function() {
        hd.toBase58(true)
      }, /Missing private key/);
      done();
    })
  })

  describe('fromBase58', function() {
    fixtures.valid.forEach(function(f) {
      it('imports ' + f.master.base58 + ' (public) correctly', function(done) {
        var hd = HDNode.fromBase58(f.master.base58)

        assert.equal(hd.toBase58(), f.master.base58)
        done()
      });
    })

    fixtures.valid.forEach(function(f) {
      it('imports ' + f.master.base58Priv + ' (private) correctly', function(done) {
        var hd = HDNode.fromBase58(f.master.base58Priv)

        assert.equal(hd.toBase58(), f.master.base58Priv);
        done();
      })
    })

    fixtures.invalid.fromBase58.forEach(function(f) {
      it('throws on ' + f.string, function(done) {
        assert.throws(function() {
          HDNode.fromBase58(f.string)
        }, new RegExp(f.exception));
        done();
      })
    })
  })

  describe('fromBuffer/fromHex', function() {
    fixtures.valid.forEach(function(f) {
      it('imports ' + f.master.hex + ' (public) correctly', function(done) {
        var hd = HDNode.fromHex(f.master.hex)

        assert.equal(hd.toBuffer().toString('hex'), f.master.hex);
        done();
      })
    })

    fixtures.valid.forEach(function(f) {
      it('imports ' + f.master.hexPriv + ' (private) correctly', function(done) {
        var hd = HDNode.fromHex(f.master.hexPriv)

        assert.equal(hd.toBuffer().toString('hex'), f.master.hexPriv)
        done();
      })
    })

    fixtures.invalid.fromBuffer.forEach(function(f) {
      it('throws on ' + f.hex, function(done) {
        assert.throws(function() {
          HDNode.fromHex(f.hex)
        }, new RegExp(f.exception));
        done();
      })
    })
  })

  describe('toBuffer/toHex', function() {
    fixtures.valid.forEach(function(f) {
      it('exports ' + f.master.hex + ' (public) correctly', function(done) {
        var hd = HDNode.fromSeedHex(f.master.seed).neutered()

        assert.equal(hd.toHex(), f.master.hex);
        done();
      })
    })

    fixtures.valid.forEach(function(f) {
      it('exports ' + f.master.hexPriv + ' (private) correctly', function(done) {
        var hd = HDNode.fromSeedHex(f.master.seed)

        assert.equal(hd.toHex(), f.master.hexPriv);
        done();
      })
    })

    // FIXME: remove in 2.x.y
    it('fails when there is no private key', function(done) {
      var hd = HDNode.fromHex(fixtures.valid[0].master.hex)

      assert.throws(function() {
        hd.toHex(true)
      }, /Missing private key/)
      done();
    })
  })

  describe('getIdentifier', function() {
    var f = fixtures.valid[0]

    it('returns the identifier for ' + f.master.fingerprint, function(done) {
      var hd = HDNode.fromBase58(f.master.base58)

      assert.equal(hd.getIdentifier().toString('hex'), f.master.identifier);
      done();
    })
  })

  describe('getFingerprint', function() {
    var f = fixtures.valid[0]

    it('returns the fingerprint for ' + f.master.fingerprint, function(done) {
      var hd = HDNode.fromBase58(f.master.base58)

      assert.equal(hd.getFingerprint().toString('hex'), f.master.fingerprint)
      done();
    })
  })

  describe('getAddress', function() {
    var f = fixtures.valid[0]

    it('returns the Address (pubHash) for ' + f.master.fingerprint, function(done) {
      var hd = HDNode.fromBase58(f.master.base58)

      assert.equal(hd.getAddress().toString(), f.master.address)
      done();
    })

    it('supports alternative networks', function(done) {
      var hd = HDNode.fromBase58(f.master.base58)
      hd.network = networks.testnet

      assert.equal(hd.getAddress().version, networks.testnet.pubKeyHash);
      done();
    })
  })

  describe('neutered', function() {
    var f = fixtures.valid[0]

    it('strips all private information', function(done) {
      var hd = HDNode.fromBase58(f.master.base58)
      var hdn = hd.neutered()

      assert.equal(hdn.privKey, undefined)
      assert.equal(hdn.pubKey.toHex(), hd.pubKey.toHex())
      assert.equal(hdn.chainCode, hd.chainCode)
      assert.equal(hdn.depth, hd.depth)
      assert.equal(hdn.index, hd.index);
      done();
    })
  })

  describe('derive', function() {
    function verifyVector(hd, v, depth) {
      assert.equal(hd.privKey.toWIF(), v.wif)
      assert.equal(hd.pubKey.toHex(), v.pubKey)
      assert.equal(hd.chainCode.toString('hex'), v.chainCode)
      assert.equal(hd.depth, depth || 0)

      if (v.hardened) {
        assert.equal(hd.index, v.m + HDNode.HIGHEST_BIT)
      } else {
        assert.equal(hd.index, v.m)
      }
    }

    fixtures.valid.forEach(function(f, j) {
      var hd = HDNode.fromSeedHex(f.master.seed)

      // FIXME: test data is only testing Private -> private for now
      f.children.forEach(function(c, i) {
        it(c.description + ' from ' + f.master.fingerprint, function(done) {
          if (c.hardened) {
            hd = hd.deriveHardened(c.m)

          } else {
            hd = hd.derive(c.m)
          }

          verifyVector(hd, c, i + 1)
          done();
        })
      })
    })

    it('works for Private -> public (neutered)', function(done) {
      var f = fixtures.valid[1]
      var c = f.children[0]

      var master = HDNode.fromBase58(f.master.base58Priv)
      var child = master.derive(c.m).neutered()

      assert.equal(child.toBase58(), c.base58);
      done();
    })

    it('works for Private -> public (neutered, hardened)', function(done) {
      var f = fixtures.valid[0]
      var c = f.children[0]

      var master = HDNode.fromBase58(f.master.base58Priv)
      var child = master.deriveHardened(c.m).neutered()

      assert.equal(child.toBase58(), c.base58)
      done();
    })

    it('works for Public -> public', function(done) {
      var f = fixtures.valid[1]
      var c = f.children[0]

      var master = HDNode.fromBase58(f.master.base58)
      var child = master.derive(c.m)

      assert.equal(child.toBase58(), c.base58);
      done();
    })

    it('throws on Public -> public (hardened)', function(done) {
      var f = fixtures.valid[0]
      var c = f.children[0]

      var master = HDNode.fromBase58(f.master.base58)

      assert.throws(function() {
        master.deriveHardened(c.m)
      }, /Could not derive hardened child key/);
      done();
    })
  })
})
