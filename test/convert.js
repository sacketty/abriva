var Lab = require('lab');
var assert = require('assert')
var convert = require('../lib/eccrypto/convert')

var fixtures = require('./fixtures/convert')

// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('convert', function() {
  describe('bufferToWordArray', function() {
    fixtures.valid.forEach(function(f) {
      it('converts ' + f.hex + ' correctly', function(done) {
        var buffer = new Buffer(f.hex, 'hex')
        var result = convert.bufferToWordArray(buffer)

        assert.deepEqual(result, f.wordArray)
        done();
      });
    })
  })

  describe('wordArrayToBuffer', function() {
    fixtures.valid.forEach(function(f) {
      it('converts to ' + f.hex + ' correctly', function(done) {
        var resultHex = convert.wordArrayToBuffer(f.wordArray).toString('hex')

        assert.deepEqual(resultHex, f.hex);
        done();
      });
    })
  })
})
