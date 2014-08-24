var assert = require('assert')
var opcodes = require('../lib/opcodes')

var Script = require('../lib/script')

var fixtures = require('./fixtures/script.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Script', function() {
  describe('constructor', function() {
    it('accepts valid parameters', function(done) {
      var buffer = new Buffer([1])
      var chunks = [1]
      var script = new Script(buffer, chunks)

      assert.equal(script.buffer, buffer)
      assert.equal(script.chunks, chunks)
      done()
    })

    it('throws an error when input is not an array', function(done) {
      assert.throws(function(){ new Script({}) }, /Expected Buffer, got/)
      done()
    })
  })

  describe('fromASM/toASM', function() {
    fixtures.valid.forEach(function(f) {
      it('decodes/encodes ' + f.description, function(done) {
        assert.equal(Script.fromASM(f.asm).toASM(), f.asm)
        done()
      })
    })
  })

  describe('fromHex/toHex', function() {
    fixtures.valid.forEach(function(f) {
      it('decodes/encodes ' + f.description, function(done) {
        assert.equal(Script.fromHex(f.hex).toHex(), f.hex)
        done()
      })
    })
  })

  describe('getHash', function() {
    fixtures.valid.forEach(function(f) {
      it('produces a HASH160 of \"' + f.asm + '\"', function(done) {
        var script = Script.fromHex(f.hex)

        assert.equal(script.getHash().toString('hex'), f.hash)
        done()
      })
    })
  })

  describe('fromChunks', function() {
    it('should match expected behaviour', function(done) {
      var hash = new Buffer(32)
      hash.fill(0)

      var script = Script.fromChunks([
        opcodes.OP_HASH160,
        hash,
        opcodes.OP_EQUAL
      ])

      assert.equal(script.toHex(), 'a920000000000000000000000000000000000000000000000000000000000000000087')
      done()
    })
  })

  describe('without', function() {
    var hex = 'a914e8c300c87986efa94c37c0519929019ef86eb5b487'
    var script = Script.fromHex(hex)

    it('should return a script without the given value', function(done) {
      var subScript = script.without(opcodes.OP_HASH160)

      assert.equal(subScript.toHex(), '14e8c300c87986efa94c37c0519929019ef86eb5b487')
      done()
    })

    it('shouldnt mutate the original script', function(done) {
      var subScript = script.without(opcodes.OP_EQUAL)

      assert.notEqual(subScript.toHex(), hex)
      assert.equal(script.toHex(), hex)
      done()
    })
  })
})
