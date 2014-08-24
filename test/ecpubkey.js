var assert = require('assert')
var crypto = require('../lib/eccrypto/crypto')
var networks = require('../lib/networks')

var BigInteger = require('bigi')
var ECPubKey = require('../lib/eccrypto/ecpubkey')

var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')

var fixtures = require('./fixtures/ecpubkey.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var beforeEach = Lab.beforeEach;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('ECPubKey', function() {
  var Q

  beforeEach(function(done) {
    Q = ecurve.Point.fromAffine(
      curve,
      new BigInteger(fixtures.Q.x),
      new BigInteger(fixtures.Q.y)
    )
    done()
  })

  describe('constructor', function() {
    it('defaults to compressed', function(done) {
      var pubKey = new ECPubKey(Q)

      assert.equal(pubKey.compressed, true)
      done()
    })

    it('supports the uncompressed flag', function(done) {
      var pubKey = new ECPubKey(Q, false)

      assert.equal(pubKey.compressed, false)
      done()
    })
  })

  describe('fromHex/toHex', function() {
    it('supports compressed points', function(done) {
      var pubKey = ECPubKey.fromHex(fixtures.compressed.hex)

      assert(pubKey.Q.equals(Q))
      assert.equal(pubKey.toHex(), fixtures.compressed.hex)
      assert.equal(pubKey.compressed, true)
      done()
    })

    it('supports uncompressed points', function(done) {
      var pubKey = ECPubKey.fromHex(fixtures.uncompressed.hex)

      assert(pubKey.Q.equals(Q))
      assert.equal(pubKey.toHex(), fixtures.uncompressed.hex)
      assert.equal(pubKey.compressed, false)
      done()
    })
  })

  describe('getAddress', function() {
    it('calculates the expected hash (compressed)', function(done) {
      var pubKey = new ECPubKey(Q, true)
      var address = pubKey.getAddress()

      assert.equal(address.hash.toString('hex'), fixtures.compressed.hash160)
      done()
    })

    it('calculates the expected hash (uncompressed)', function(done) {
      var pubKey = new ECPubKey(Q, false)
      var address = pubKey.getAddress()

      assert.equal(address.hash.toString('hex'), fixtures.uncompressed.hash160)
      done()
    })

    it('supports alternative networks', function(done) {
      var pubKey = new ECPubKey(Q)
      var address = pubKey.getAddress(networks.testnet)

      assert.equal(address.version, networks.testnet.pubKeyHash)
      assert.equal(address.hash.toString('hex'), fixtures.compressed.hash160)
      done()
    })
  })

  describe('verify', function() {
    var pubKey, signature
    beforeEach(function(done) {
      pubKey = new ECPubKey(Q)

      signature = {
        r: new BigInteger(fixtures.signature.r),
        s: new BigInteger(fixtures.signature.s)
      }
      done()
    })

    it('verifies a valid signature', function(done) {
      var hash = crypto.sha256(fixtures.message)

      assert(pubKey.verify(hash, signature))
      done()
    })

    it('doesn\'t verify the wrong signature', function(done) {
      var hash = crypto.sha256('mushrooms')

      assert(!pubKey.verify(hash, signature))
      done()
    })
  })
})
