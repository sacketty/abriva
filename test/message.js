var assert = require('assert')
var networks = require('../lib/networks')

var Address = require('../lib/address')
var BigInteger = require('bigi')
var ECKey = require('../lib/eccrypto/eckey')
var Message = require('../lib/message')

var fixtures = require('./fixtures/message.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('Message', function() {
  describe('magicHash', function() {
    fixtures.valid.magicHash.forEach(function(f) {
      it('produces the correct magicHash for \"' + f.message + '\" (' + f.network + ')', function(done) {
        var network = networks[f.network]
        var actual = Message.magicHash(f.message, network)

        assert.equal(actual.toString('hex'), f.magicHash)
        done()
      })
    })
  })

  describe('verify', function() {
    it('accepts an Address object', function(done) {
      var f = fixtures.valid.verify[0]
      var network = networks[f.network]

      var address = Address.fromBase58Check(f.address)
      assert(Message.verify(address, f.signature, f.message, network))
      done()
    })

    fixtures.valid.verify.forEach(function(f) {
      it('verifies a valid signature for \"' + f.message + '\" (' + f.network + ')', function(done) {
        var network = networks[f.network]

        var signature = f.signature
        assert(Message.verify(f.address, f.signature, f.message, network))

        if (f.compressed) {
          assert(Message.verify(f.compressed.address, f.compressed.signature, f.message, network))
        }
        done()
      })
    })

    fixtures.invalid.verify.forEach(function(f) {
      it(f.description, function(done) {
        assert(!Message.verify(f.address, f.signature, f.message))
        done()
      })
    })
  })

  describe('signing', function() {
    fixtures.valid.signing.forEach(function(f) {
      it(f.description, function(done) {
        var network = networks[f.network]

        var privKey = new ECKey(new BigInteger(f.d), false)
        var signature = Message.sign(privKey, f.message, network)
        assert.equal(signature.toString('base64'), f.signature)

        if (f.compressed) {
          var compressedPrivKey = new ECKey(new BigInteger(f.d))
          var compressedSignature = Message.sign(compressedPrivKey, f.message)

          assert.equal(compressedSignature.toString('base64'), f.compressed.signature)
        }
        done()
      })
    })
  })
})
