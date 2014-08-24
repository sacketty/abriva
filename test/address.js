var assert = require('assert')
var networks = require('../lib/networks')

var Address = require('../lib/address')
var Script = require('../lib/script')

var fixtures = require('./fixtures/address.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Address', function() {
  describe('Constructor', function() {
    it('does not mutate the input', function(done) {
      fixtures.valid.forEach(function(f) {
        var hash = new Buffer(f.hex, 'hex')
        var addr = new Address(hash, f.version)

        assert.equal(addr.version, f.version)
        assert.equal(addr.hash.toString('hex'), f.hex)
      })
      done()
    })
  })

  describe('fromBase58Check', function() {
    fixtures.valid.forEach(function(f) {
      it('imports ' + f.description + '(' + f.network + ') correctly', function(done) {
        var addr = Address.fromBase58Check(f.base58check)

        assert.equal(addr.version, f.version)
        assert.equal(addr.hash.toString('hex'), f.hex)
        done()
      })
    })

    fixtures.invalid.fromBase58Check.forEach(function(f) {
      it('throws on ' + f.description, function(done) {
        assert.throws(function() {
          Address.fromBase58Check(f.base58check)
        }, new RegExp(f.exception))
        done()
      })
    })
  })

  describe('fromOutputScript', function() {
    fixtures.valid.forEach(function(f) {
      it('imports ' + f.description + '(' + f.network + ') correctly', function(done) {
        var script = Script.fromHex(f.script)
        var addr = Address.fromOutputScript(script, networks[f.network])

        assert.equal(addr.version, f.version)
        assert.equal(addr.hash.toString('hex'), f.hex)
        done()
      })
    })

    fixtures.invalid.fromOutputScript.forEach(function(f) {
      it('throws when ' + f.description, function(done) {
        var script = Script.fromHex(f.hex)

        assert.throws(function() {
          Address.fromOutputScript(script)
        }, new RegExp(f.description))
        done()
      })
    })
  })

  describe('toBase58Check', function() {
    fixtures.valid.forEach(function(f) {
      it('exports ' + f.description + '(' + f.network + ') correctly', function(done) {
        var addr = Address.fromBase58Check(f.base58check)
        var result = addr.toBase58Check()

        assert.equal(result, f.base58check)
        done()
      })
    })
  })

  describe('toOutputScript', function() {
    fixtures.valid.forEach(function(f) {
      it('imports ' + f.description + '(' + f.network + ') correctly', function(done) {
        var addr = Address.fromBase58Check(f.base58check)
        var script = addr.toOutputScript()

        assert.equal(script.toHex(), f.script)
        done()
      })
    })

    fixtures.invalid.toOutputScript.forEach(function(f) {
      it('throws when ' + f.description, function(done) {
        var addr = new Address(new Buffer(f.hex, 'hex'), f.version)

        assert.throws(function() {
          addr.toOutputScript()
        }, new RegExp(f.description))
        done()
      })
    })
  })
})
