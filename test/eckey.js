var assert = require('assert')
var crypto = require('crypto')
var networks = require('../lib/networks')
var sinon = require('sinon')

var BigInteger = require('bigi')
var ECKey = require('../lib/eccrypto/eckey')

var fixtures = require('./fixtures/eckey.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var beforeEach = Lab.beforeEach;
var afterEach = Lab.afterEach;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('ECKey', function() {
  describe('constructor', function() {
    it('defaults to compressed', function(done) {
      var privKey = new ECKey(BigInteger.ONE)

      assert.equal(privKey.pub.compressed, true)
      done()
    })

    it('supports the uncompressed flag', function(done) {
      var privKey = new ECKey(BigInteger.ONE, false)

      assert.equal(privKey.pub.compressed, false)
      done()
    })

    fixtures.valid.forEach(function(f) {
      it('calculates the matching pubKey for ' + f.d, function(done) {
        var d = new BigInteger(f.d)
        var privKey = new ECKey(d)

        assert.equal(privKey.pub.Q.toString(), f.Q)
        done()
      })
    })

    fixtures.invalid.constructor.forEach(function(f) {
      it('throws on ' + f.d, function(done) {
        var d = new BigInteger(f.d)

        assert.throws(function() {
          new ECKey(d)
        }, new RegExp(f.exception))
        done()
      })
    })
  })

  describe('fromWIF', function() {
    fixtures.valid.forEach(function(f) {
      f.WIFs.forEach(function(wif) {
        it('imports ' + wif.string + ' correctly', function(done) {
          var privKey = ECKey.fromWIF(wif.string)

          assert.equal(privKey.d.toString(), f.d)
          assert.equal(privKey.pub.compressed, wif.compressed)
          done()
        })
      })
    })

    fixtures.invalid.WIF.forEach(function(f) {
      it('throws on ' + f.string, function(done) {
        assert.throws(function() {
          ECKey.fromWIF(f.string)
        }, new RegExp(f.exception))
        done()
      })
    })
  })

  describe('toWIF', function() {
    fixtures.valid.forEach(function(f) {
      f.WIFs.forEach(function(wif) {
        it('exports ' + wif.string + ' correctly', function(done) {
          var privKey = ECKey.fromWIF(wif.string)
          var network = networks[wif.network]
          var result = privKey.toWIF(network)

          assert.equal(result, wif.string)
          done()
        })
      })
    })
  })

  describe('makeRandom', function() {
    var exWIF = 'KwMWvwRJeFqxYyhZgNwYuYjbQENDAPAudQx5VEmKJrUZcq6aL2pv'
    var exPrivKey = ECKey.fromWIF(exWIF)
    var exBuffer = exPrivKey.d.toBuffer(32)

    describe('uses default crypto RNG', function() {
      beforeEach(function(done) {
        sinon.stub(crypto, 'randomBytes').returns(exBuffer)
        done()
      })

      afterEach(function(done) {
        crypto.randomBytes.restore()
        done()
      })

      it('generates a ECKey', function(done) {
        var privKey = ECKey.makeRandom()

        assert.equal(privKey.toWIF(), exWIF)
        done()
      })

      it('supports compression', function(done) {
        assert.equal(ECKey.makeRandom(true).pub.compressed, true)
        assert.equal(ECKey.makeRandom(false).pub.compressed, false)
        done()
      })
    })

    it('allows a custom RNG to be used', function(done) {
      function rng(size) {
        return exBuffer.slice(0, size)
      }

      var privKey = ECKey.makeRandom(undefined, rng)
      assert.equal(privKey.toWIF(), exWIF)
      done()
    })
  })

  describe('signing', function() {
    var hash = crypto.randomBytes(32)
    var priv = ECKey.makeRandom()
    var signature = priv.sign(hash)

    it('should verify against the public key', function(done) {
      assert(priv.pub.verify(hash, signature))
      done()
    })

    it('should not verify against the wrong public key', function(done) {
      var priv2 = ECKey.makeRandom()

      assert(!priv2.pub.verify(hash, signature))
      done()
    })
  })
})
