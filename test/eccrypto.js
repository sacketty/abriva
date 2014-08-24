var assert = require('assert')
var crypto = require('../lib/eccrypto/crypto')

var fixtures = require('./fixtures/crypto.json')

var Lab = require('lab');
// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('Crypto', function() {
  describe('HASH160', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var actual = crypto.hash160(data).toString('hex')

        assert.equal(actual, fixtures.after.hash160[i]);
      })
      done();
    })
  })

  describe('HASH256', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var actual = crypto.hash256(data).toString('hex')

        assert.equal(actual, fixtures.after.hash256[i]);
      })
      done();
    })
  })

  describe('RIPEMD160', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var actual = crypto.ripemd160(data).toString('hex')

        assert.equal(actual, fixtures.after.ripemd160[i]);
      })
      done();
    })
  })

  describe('SHA1', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var actual = crypto.sha1(data).toString('hex')

        assert.equal(actual, fixtures.after.sha1[i]);
      })
      done();
    })
  })

  describe('SHA256', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var actual = crypto.sha256(data).toString('hex')

        assert.equal(actual, fixtures.after.sha256[i]);
      })
      done();
    })
  })

  describe('HmacSHA256', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var secret = new Buffer(fixtures.before.secret)
        var actual = crypto.HmacSHA256(data, secret).toString('hex')

        assert.equal(actual, fixtures.after.hmacsha256[i]);
      })
      done();
    })
  })

  describe('HmacSHA512', function() {
    it('matches the test vectors', function(done) {
      fixtures.before.hex.forEach(function(hex, i) {
        var data = new Buffer(hex, 'hex')
        var secret = new Buffer(fixtures.before.secret)
        var actual = crypto.HmacSHA512(data, secret).toString('hex')

        assert.equal(actual, fixtures.after.hmacsha512[i]);
      })
      done();
    })
  })
})
