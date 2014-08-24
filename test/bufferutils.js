var assert = require('assert')
var bufferutils = require('../lib/bufferutils')

var fixtures = require('./fixtures/bufferutils.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('bufferutils', function() {
  describe('pushDataSize', function() {
    fixtures.valid.forEach(function(f) {
      it('determines the pushDataSize of ' + f.dec + ' correctly', function(done) {
        if (!f.hexPD) return done()

        var size = bufferutils.pushDataSize(f.dec)

        assert.equal(size, f.hexPD.length / 2)
        done()
      })
    })
  })

  describe('readPushDataInt', function() {
    fixtures.valid.forEach(function(f) {
      if (!f.hexPD) return

      it('decodes ' + f.hexPD + ' correctly', function(done) {
        var buffer = new Buffer(f.hexPD, 'hex')
        var d = bufferutils.readPushDataInt(buffer, 0)
        var fopcode = parseInt(f.hexPD.substr(0, 2), 16)

        assert.equal(d.opcode, fopcode)
        assert.equal(d.number, f.dec)
        assert.equal(d.size, buffer.length)
        done()
      })
    })
  })

  describe('readUInt64LE', function() {
    fixtures.valid.forEach(function(f) {
      it('decodes ' + f.hex64 + ' correctly', function(done) {
        var buffer = new Buffer(f.hex64, 'hex')
        var number = bufferutils.readUInt64LE(buffer, 0)

        assert.equal(number, f.dec)
        done()
      })
    })

    fixtures.invalid.forEach(function(f) {
      it('throws on ' + f.description, function(done) {
        var buffer = new Buffer(f.hex64, 'hex')

        assert.throws(function() {
          bufferutils.readUInt64LE(buffer, 0)
        }, new RegExp(f.exception))
        done()
      })
    })
  })

  describe('readVarInt', function() {
    fixtures.valid.forEach(function(f) {
      it('decodes ' + f.hexVI + ' correctly', function(done) {
        var buffer = new Buffer(f.hexVI, 'hex')
        var d = bufferutils.readVarInt(buffer, 0)

        assert.equal(d.number, f.dec)
        assert.equal(d.size, buffer.length)
        done()
      })
    })

    fixtures.invalid.forEach(function(f) {
      it('throws on ' + f.description, function(done) {
        var buffer = new Buffer(f.hexVI, 'hex')

        assert.throws(function() {
          bufferutils.readVarInt(buffer, 0)
        }, new RegExp(f.exception))
        done()
      })
    })
  })

  describe('varIntSize', function() {
    fixtures.valid.forEach(function(f) {
      it('determines the varIntSize of ' + f.dec + ' correctly', function(done) {
        var size = bufferutils.varIntSize(f.dec)

        assert.equal(size, f.hexVI.length / 2)
        done()
      })
    })
  })

  describe('writePushDataInt', function() {
    fixtures.valid.forEach(function(f, i) {
      if (!f.hexPD) return

      it('encodes ' + f.dec + ' correctly', function(done) {
        var buffer = new Buffer(5)
        buffer.fill(0)

        var n = bufferutils.writePushDataInt(buffer, f.dec, 0)
        assert.equal(buffer.slice(0, n).toString('hex'), f.hexPD)
        done()
      })
    })
  })

  describe('writeUInt64LE', function() {
    fixtures.valid.forEach(function(f) {
      it('encodes ' + f.dec + ' correctly', function(done) {
        var buffer = new Buffer(8)
        buffer.fill(0)

        bufferutils.writeUInt64LE(buffer, f.dec, 0)
        assert.equal(buffer.toString('hex'), f.hex64)
        done()
      })
    })

    fixtures.invalid.forEach(function(f) {
      it('throws on ' + f.description, function(done) {
        var buffer = new Buffer(8)
        buffer.fill(0)

        assert.throws(function() {
          bufferutils.writeUInt64LE(buffer, f.dec, 0)
        }, new RegExp(f.exception))
        done()
      })
    })
  })

  describe('writeVarInt', function() {
    fixtures.valid.forEach(function(f) {
      it('encodes ' + f.dec + ' correctly', function(done) {
        var buffer = new Buffer(9)
        buffer.fill(0)

        var n = bufferutils.writeVarInt(buffer, f.dec, 0)
        assert.equal(buffer.slice(0, n).toString('hex'), f.hexVI)
        done()
      })
    })

    fixtures.invalid.forEach(function(f) {
      it('throws on ' + f.description, function(done) {
        var buffer = new Buffer(9)
        buffer.fill(0)

        assert.throws(function() {
          bufferutils.writeVarInt(buffer, f.dec, 0)
        }, new RegExp(f.exception))
        done()
      })
    })
  })
})
