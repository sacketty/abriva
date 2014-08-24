var assert = require('assert')
var scripts = require('../lib/scripts')

var Address = require('../lib/address')
var ECPubKey = require('../lib/eccrypto/ecpubkey')
var Script = require('../lib/script')

var fixtures = require('./fixtures/scripts.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('Scripts', function() {
  describe('classifyInput', function() {
    fixtures.valid.forEach(function(f) {
      if (!f.scriptSig) return

      it('classifies ' + f.scriptSig + ' as ' + f.type, function(done) {
        var script = Script.fromASM(f.scriptSig)
        var type = scripts.classifyInput(script)

        assert.equal(type, f.type)
        done()
      })
    })
  })

  describe('classifyOutput', function() {
    fixtures.valid.forEach(function(f) {
      if (!f.scriptPubKey) return

      it('classifies ' + f.scriptPubKey + ' as ' + f.type, function(done) {
        var script = Script.fromASM(f.scriptPubKey)
        var type = scripts.classifyOutput(script)

        assert.equal(type, f.type)
        done()
      })
    })

    fixtures.invalid.classify.forEach(function(f) {
      it('returns nonstandard for ' + f.description, function(done) {
        var script = Script.fromASM(f.scriptPubKey)
        var type = scripts.classifyOutput(script)

        assert.equal(type, 'nonstandard')
        done()
      })
    })
  })

  describe('pubKey', function() {
    fixtures.valid.forEach(function(f) {
      if (f.type !== 'pubkey') return

      describe('input script', function() {
        it('is generated correctly for ' + f.pubKey, function(done) {
          var signature = new Buffer(f.signature, 'hex')

          var scriptSig = scripts.pubKeyInput(signature)
          assert.equal(scriptSig.toASM(), f.scriptSig)
          done()
        })
      })

      describe('output script', function() {
        it('is generated correctly for ' + f.pubKey, function(done) {
          var pubKey = ECPubKey.fromHex(f.pubKey)

          var scriptPubKey = scripts.pubKeyOutput(pubKey)
          assert.equal(scriptPubKey.toASM(), f.scriptPubKey)
          done()
        })
      })
    })
  })

  describe('pubKeyHash', function() {
    fixtures.valid.forEach(function(f) {
      if (f.type !== 'pubkeyhash') return

      var pubKey = ECPubKey.fromHex(f.pubKey)
      var address = pubKey.getAddress()

      describe('input script', function() {
        it('is generated correctly for ' + address, function(done) {
          var signature = new Buffer(f.signature, 'hex')

          var scriptSig = scripts.pubKeyHashInput(signature, pubKey)
          assert.equal(scriptSig.toASM(), f.scriptSig)
          done()
        })
      })

      describe('output script', function() {
        it('is generated correctly for ' + address, function(done) {
          var scriptPubKey = scripts.pubKeyHashOutput(address.hash)
          assert.equal(scriptPubKey.toASM(), f.scriptPubKey)
          done()
        })
      })
    })
  })

  describe('multisig', function() {
    fixtures.valid.forEach(function(f) {
      if (f.type !== 'multisig') return

      var pubKeys = f.pubKeys.map(ECPubKey.fromHex)
      var scriptPubKey = scripts.multisigOutput(pubKeys.length, pubKeys)

      describe('input script', function() {
        it('is generated correctly for ' + f.scriptPubKey, function(done) {
          var signatures = f.signatures.map(function(signature) {
            return new Buffer(signature, 'hex')
          })

          var scriptSig = scripts.multisigInput(signatures)
          assert.equal(scriptSig.toASM(), f.scriptSig)
          done()
        })
      })

      describe('output script', function() {
        it('is generated correctly for ' + f.scriptPubKey, function(done) {
          assert.equal(scriptPubKey.toASM(), f.scriptPubKey)
          done()
        })
      })
    })

    fixtures.invalid.multisig.forEach(function(f) {
      var pubKeys = f.pubKeys.map(ECPubKey.fromHex)
      var scriptPubKey = scripts.multisigOutput(pubKeys.length, pubKeys)

      if (f.scriptPubKey) {
        describe('output script', function() {
          it('throws on ' + f.exception, function(done) {
            assert.throws(function() {
              scripts.multisigOutput(f.m, pubKeys)
            }, new RegExp(f.exception))
            done()
          })
        })
      } else {
        describe('input script', function() {
          it('throws on ' + f.exception, function(done) {
            var signatures = f.signatures.map(function(signature) {
              return new Buffer(signature, 'hex')
            })

            assert.throws(function() {
              scripts.multisigInput(signatures, scriptPubKey)
            }, new RegExp(f.exception))
            done()
          })
        })
      }
    })
  })

  describe('scripthash', function() {
    fixtures.valid.forEach(function(f) {
      if (f.type !== 'scripthash') return

      var redeemScript = Script.fromASM(f.redeemScript)
      var redeemScriptSig = Script.fromASM(f.redeemScriptSig)

      var address = Address.fromOutputScript(Script.fromASM(f.scriptPubKey))

      describe('input script', function() {
        it('is generated correctly for ' + address, function(done) {
          var scriptSig = scripts.scriptHashInput(redeemScriptSig, redeemScript)

          assert.equal(scriptSig.toASM(), f.scriptSig)
          done()
        })
      })

      describe('output script', function() {
        it('is generated correctly for ' + address, function(done) {
          var scriptPubKey = scripts.scriptHashOutput(redeemScript.getHash())

          assert.equal(scriptPubKey.toASM(), f.scriptPubKey)
          done()
        })
      })
    })
  })
})
