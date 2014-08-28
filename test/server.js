// Load modules

var Url = require('url');
var Lab = require('lab');
var Abriva = require('../lib');


//TODO REmove
var util = require('util')



// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Abriva', function () {

    describe('server', function () {

        var credentialsFunc = function (id, callback) {

            var credentials = {
                adr: id,
                key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                algorithm:  'sha256',
                user: 'steve'
            };

            return callback(null, credentials);
        };

        describe('#authenticate', function () {

            it('parses a valid authentication header (sha1)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353788437", nonce="k3j4h2", mac="HzGmN8kYgcfVegTpMvdgmlgmjNVOHjemS6zy1H8W2c3TRiaB+LV7htPeajemw079WU5gAWZTBD9KMNSCMe42evo=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    done();
                });
            });

            it('parses a valid authentication header (sha256)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/1?b=1&a=2',
                    host: 'example.com',
                    port: 8000,
                    authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353832234", nonce="j4h3g2", mac="IO1dSuDJ6i9XONAIXb/aPdUB56YUnIAI5iCQRyGWd+yxVsj9WU2CXo9whaatRdsiEDHe8YI/3I1VFvHhWTV2FSo=", ext="some-app-data"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353832234000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    done();
                });
            });

            it('parses a valid authentication header (host override)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example1.com:8080',
                        authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353788437", nonce="k3j4h2", mac="HzGmN8kYgcfVegTpMvdgmlgmjNVOHjemS6zy1H8W2c3TRiaB+LV7htPeajemw079WU5gAWZTBD9KMNSCMe42evo=", ext="hello"'
                    }
                };

                Abriva.server.authenticate(req, credentialsFunc, { host: 'example.com', localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    done();
                });
            });

            it('parses a valid authentication header (host port override)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example1.com:80',
                        authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353788437", nonce="k3j4h2", mac="HzGmN8kYgcfVegTpMvdgmlgmjNVOHjemS6zy1H8W2c3TRiaB+LV7htPeajemw079WU5gAWZTBD9KMNSCMe42evo=", ext="hello"'
                    }
                };

                Abriva.server.authenticate(req, credentialsFunc, { host: 'example.com', port: 8080, localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    done();
                });
            });

            it('parses a valid authentication header (POST with payload)', function (done) {

                var req = {
                    method: 'POST',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1357926341", nonce="1AwuJD", hash="qAiXIVv+yjDATneWxZP2YCTa9aHRgQdnH9b3Wc+o3dg=", ext="some-app-data", mac="H6u/OVQsrGin4AOdxo3eVW09WL/dMfIIxGrcK2OC+XmfD0qmh9+pLe92j1SgDehsE9q9xSXaFsWW93GDyrHlolk="'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1357926341000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');
                    done();
                });
            });

            it('errors on missing hash', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/1?b=1&a=2',
                    host: 'example.com',
                    port: 8000,
                    authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353832234", nonce="j4h3g2", mac="IO1dSuDJ6i9XONAIXb/aPdUB56YUnIAI5iCQRyGWd+yxVsj9WU2CXo9whaatRdsiEDHe8YI/3I1VFvHhWTV2FSo=", ext="some-app-data"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { payload: 'body', localtimeOffsetMsec: 1353832234000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Missing required payload hash');
                    done();
                });
            });

            it('errors on a stale timestamp', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1362337299", nonce="UzmxSs", ext="some-app-data", mac="H2d65iNl/mWZ1y2M2+WD0f2N7nOJTewbb3/vyxYekFIbYLLsDQlmCBh7hFUGX/wo7OZn+A+1eP0R5s+jx6aXuU8="'
                };

                Abriva.server.authenticate(req, credentialsFunc, {}, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Stale timestamp');
                    var header = err.output.headers['WWW-Authenticate'];
                    var ts = header.match(/^Abriva ts\=\"(\d+)\"\, tsm\=\"([^\"]+)\"\, error=\"Stale timestamp\"$/);
                    var now = Abriva.utils.now();
                    expect(parseInt(ts[1], 10) * 1000).to.be.within(now - 1000, now + 1000);

                    var res = {
                        headers: {
                            'www-authenticate': header
                        }
                    };

                    expect(Abriva.client.authenticate(res, credentials, artifacts)).to.equal(true);
                    done();
                });
            });

            it('errors on a replay', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK", ts="1353788437", nonce="k3j4h2", mac="HzGmN8kYgcfVegTpMvdgmlgmjNVOHjemS6zy1H8W2c3TRiaB+LV7htPeajemw079WU5gAWZTBD9KMNSCMe42evo=", ext="hello"'
                };

                var memoryCache = {};
                var options = {
                    localtimeOffsetMsec: 1353788437000 - Abriva.utils.now(),
                    nonceFunc: function (nonce, ts, callback) {

                        if (memoryCache[nonce]) {
                            return callback(new Error());
                        }

                        memoryCache[nonce] = true;
                        return callback();
                    }
                };

                Abriva.server.authenticate(req, credentialsFunc, options, function (err, credentials, artifacts) {

                    expect(err).to.not.exist;
                    expect(credentials.user).to.equal('steve');

                    Abriva.server.authenticate(req, credentialsFunc, options, function (err, credentials, artifacts) {

                        expect(err).to.exist;
                        expect(err.output.payload.message).to.equal('Invalid nonce');
                        done();
                    });
                });
            });

            it('errors on an invalid authentication header: wrong scheme', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Basic asdasdasdasd'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.not.exist;
                    done();
                });
            });

            it('errors on an invalid authentication header: no scheme', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: '!@#'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Invalid header syntax');
                    done();
                });
            });

            it('errors on an missing authorization header', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080
                };

                Abriva.server.authenticate(req, credentialsFunc, {}, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.isMissing).to.equal(true);
                    done();
                });
            });

            it('errors on an missing host header', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    headers: {
                        authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                    }
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Invalid Host header');
                    done();
                });
            });

            it('errors on an missing authorization attribute (id)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Missing attributes');
                    done();
                });
            });

            it('errors on an missing authorization attribute (ts)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Missing attributes');
                    done();
                });
            });

            it('errors on an missing authorization attribute (nonce)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Missing attributes');
                    done();
                });
            });

            it('errors on an missing authorization attribute (mac)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Missing attributes');
                    done();
                });
            });

            it('errors on an unknown authorization attribute', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", x="3", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Unknown attribute: x');
                    done();
                });
            });

            it('errors on an bad authorization header format', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123\\", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Bad header format');
                    done();
                });
            });

            it('errors on an bad authorization attribute value', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="\t", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Bad attribute value: adr');
                    done();
                });
            });

            it('errors on an empty authorization attribute value', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Bad attribute value: adr');
                    done();
                });
            });

            it('errors on duplicated authorization attribute key', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", adr="456", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Duplicate attribute: adr');
                    done();
                });
            });

            it('errors on an invalid authorization header format', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva'
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Invalid header syntax');
                    done();
                });
            });

            it('errors on an bad host header (missing host)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: ':8080',
                        authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                    }
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Invalid Host header');
                    done();
                });
            });

            it('errors on an bad host header (pad port)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    headers: {
                        host: 'example.com:something',
                        authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                    }
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Invalid Host header');
                    done();
                });
            });

            it('errors on credentialsFunc error', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    return callback(new Error('Unknown user'));
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Unknown user');
                    done();
                });
            });

            it('errors on credentialsFunc error (with credentials)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    return callback(new Error('Unknown user'), { some: 'value' });
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Unknown user');
                    expect(credentials.some).to.equal('value');
                    done();
                });
            });

            it('errors on missing credentials', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    return callback(null, null);
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Unknown credentials');
                    done();
                });
            });

            it('errors on invalid credentials (id)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    var credentials = {
                        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        user: 'steve'
                    };

                    return callback(null, credentials);
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Invalid credentials');
                    expect(err.output.payload.message).to.equal('An internal server error occurred');
                    done();
                });
            });

            it('errors on invalid credentials (key)', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    var credentials = {
                        address: '23434d3q4d5345d',
                        user: 'steve'
                    };

                    return callback(null, credentials);
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Invalid credentials');
                    expect(err.output.payload.message).to.equal('An internal server error occurred');
                    done();
                });
            });

            it('errors on unknown credentials algorithm', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="/qwS4UjfVWMcUyW6EEgUH4jlr7T/wuKe3dKijvTvSos=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    var credentials = {
                        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        algorithm: 'hmac-sha-0',
                        user: 'steve'
                    };

                    return callback(null, credentials);
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Unknown algorithm');
                    expect(err.output.payload.message).to.equal('An internal server error occurred');
                    done();
                });
            });

            it('errors on unknown bad mac', function (done) {

                var req = {
                    method: 'GET',
                    url: '/resource/4?filter=a',
                    host: 'example.com',
                    port: 8080,
                    authorization: 'Abriva adr="123", ts="1353788437", nonce="k3j4h2", mac="HzGmN8kYgcfVegTpMvdgmlgmjNVOHjemS6zy1H8W2c3TRiaB+LV7htPeajemw079WU5gAWZTBD9KMNSCMe42evo=", ext="hello"'
                };

                var credentialsFunc = function (id, callback) {

                    var credentials = {
                        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                        algorithm: 'sha256',
                        user: 'steve'
                    };

                    return callback(null, credentials);
                };

                Abriva.server.authenticate(req, credentialsFunc, { localtimeOffsetMsec: 1353788437000 - Abriva.utils.now() }, function (err, credentials, artifacts) {

                    expect(err).to.exist;
                    expect(err.output.payload.message).to.equal('Bad mac');
                    done();
                });
            });
        });

        describe('#header', function () {

            it('generates header', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    ext: 'some-app-data',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var header = Abriva.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('Abriva mac=\"IIdfUOXSV8vVz5no5u+p1ruan1mIiOB61HqNAdIPHnD3JiJKdRvnv24YebFqraSBuBnlH9nKx3twtKUW+sVsZgk=\", hash=\"Bn8OiCB6zOHTKGtRrZY47DgOxWfvXqqrW8fomUhPnKs=\", ext=\"response-specific\"');
                done();
            });

            it('generates header (empty payload)', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    ext: 'some-app-data',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var header = Abriva.server.header(credentials, artifacts, { payload: '', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('Abriva mac=\"H2izJqgjMQcmBG8/mbKJ41CuXe14ewo0zyhjV3prNVqPf7JMLC5onHGjH1ZJ7TW6olHqLjKGo9R+bZrRKHuQKk0=\", hash=\"YPCMpoNSclS8I+imNQJ1Fggfm2LPjpjnV1IA7NHSsVg=\", ext=\"response-specific\"');
                done();
            });

            it('generates header (pre calculated hash)', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    ext: 'some-app-data',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var options = { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' };
                options.hash = Abriva.crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
                var header = Abriva.server.header(credentials, artifacts, options);
                expect(header).to.equal('Abriva mac=\"IIdfUOXSV8vVz5no5u+p1ruan1mIiOB61HqNAdIPHnD3JiJKdRvnv24YebFqraSBuBnlH9nKx3twtKUW+sVsZgk=\", hash=\"Bn8OiCB6zOHTKGtRrZY47DgOxWfvXqqrW8fomUhPnKs=\", ext=\"response-specific\"');
                done();
            });

            it('generates header (null ext)', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var header = Abriva.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: null });
                expect(header).to.equal('Abriva mac=\"IKe70g2GIbli6sGrQgXU2C8ErSLmdhgsc57Yv/lmBDYBYRTI8jaRBTxbYOBXNhXUiCiPYlXED4jhHSi2IPZYeSY=\", hash=\"Bn8OiCB6zOHTKGtRrZY47DgOxWfvXqqrW8fomUhPnKs=\"');
                done();
            });

            it('errors on missing artifacts', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var header = Abriva.server.header(credentials, null, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('');
                done();
            });

            it('errors on invalid artifacts', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var header = Abriva.server.header(credentials, 5, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('');
                done();
            });

            it('errors on missing credentials', function (done) {

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    ext: 'some-app-data',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var header = Abriva.server.header(null, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('');
                done();
            });

            it('errors on invalid credentials (key)', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    algorithm: 'sha256',
                    user: 'steve'
                };

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    ext: 'some-app-data',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var header = Abriva.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('');
                done();
            });

            it('errors on invalid algorithm', function (done) {

                var credentials = {
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK',
                    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
                    algorithm: 'x',
                    user: 'steve'
                };

                var artifacts = {
                    method: 'POST',
                    host: 'example.com',
                    port: '8080',
                    resource: '/resource/4?filter=a',
                    ts: '1398546787',
                    nonce: 'xUwusx',
                    hash: 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
                    ext: 'some-app-data',
                    mac: 'dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=',
                    address: '18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK'
                };

                var header = Abriva.server.header(credentials, artifacts, { payload: 'some reply', contentType: 'text/plain', ext: 'response-specific' });
                expect(header).to.equal('');
                done();
            });
        });

        describe('#authenticateMessage', function () {

            it('errors on invalid authorization (ts)', function (done) {

                credentialsFunc('18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK', function (err, credentials) {

                    var auth = Abriva.client.message('example.com', 8080, 'some message', { credentials: credentials });
                    delete auth.ts;

                    Abriva.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, {}, function (err, credentials) {

                        expect(err).to.exist;
                        expect(err.message).to.equal('Invalid authorization');
                        done();
                    });
                });
            });

            it('errors on invalid authorization (nonce)', function (done) {

                credentialsFunc('18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK', function (err, credentials) {

                    var auth = Abriva.client.message('example.com', 8080, 'some message', { credentials: credentials });
                    delete auth.nonce;

                    Abriva.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, {}, function (err, credentials) {

                        expect(err).to.exist;
                        expect(err.message).to.equal('Invalid authorization');
                        done();
                    });
                });
            });

            it('errors on invalid authorization (hash)', function (done) {

                credentialsFunc('18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK', function (err, credentials) {

                    var auth = Abriva.client.message('example.com', 8080, 'some message', { credentials: credentials });
                    delete auth.hash;

                    Abriva.server.authenticateMessage('example.com', 8080, 'some message', auth, credentialsFunc, {}, function (err, credentials) {

                        expect(err).to.exist;
                        expect(err.message).to.equal('Invalid authorization');
                        done();
                    });
                });
            });

            it('errors with credentials', function (done) {

                credentialsFunc('18ZXvspTuGR8ac4XF3EHGegy6df93vcVzK', function (err, credentials) {

                    var auth = Abriva.client.message('example.com', 8080, 'some message', { credentials: credentials });

                    Abriva.server.authenticateMessage('example.com', 8080, 'some message', auth, function (id, callback) { callback(new Error('something'), { some: 'value' }); }, {}, function (err, credentials) {

                        expect(err).to.exist;
                        expect(err.message).to.equal('something');
                        expect(credentials.some).to.equal('value');
                        done();
                    });
                });
            });
        });

        describe('#authenticatePayloadHash', function () {

            it('checks payload hash', function (done) {

                expect(Abriva.server.authenticatePayloadHash('abcdefg', { hash: 'abcdefg' })).to.equal(true);
                expect(Abriva.server.authenticatePayloadHash('1234567', { hash: 'abcdefg' })).to.equal(false);
                done();
            });
        });
    });
});
