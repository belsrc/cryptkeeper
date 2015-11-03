var chai   = require('chai');
var assert = chai.assert;

var keeper = require('./../');



suite('Cryptkeeper', function() {

  suite('#base64Encode', function() {

    test('throws for unknown value', function() {
      assert.throws(function() {
        keeper.base64Encode();
      });
    });

    test('returns string for given string', function() {
      var actual = keeper.base64Encode('foo:bar');
      assert.isString(actual);
    });

    test('returns string for given object', function() {
      var actual = keeper.base64Encode({foo: 'bar'});
      assert.isString(actual);
    });

    test('returns string for given number', function() {
      var actual = keeper.base64Encode(156);
      assert.isString(actual);
    });

    test('returns string for given Buffer', function() {
      var actual = keeper.base64Encode(new Buffer('foo:bar'));
      assert.isString(actual);
    });

    test('returns correct value', function() {
      var actual = keeper.base64Encode('Hello world');
      var expected = 'SGVsbG8gd29ybGQ=';
      assert.strictEqual(actual, expected);
    });
  });

  suite('#base64Decode', function() {

    test('throws for unknown value', function() {
      assert.throws(function() {
        keeper.base64Decode();
      });
    });

    test('throws for non-string value', function() {
      assert.throws(function() {
        keeper.base64Decode({foo: 'bar'});
      });
    });

    test('returns string for given string', function() {
      var actual = keeper.base64Decode('SGVsbG8gd29ybGQ=');
      assert.isString(actual);
    });

    test('returns correct value', function() {
      var actual = keeper.base64Decode('SGVsbG8gd29ybGQ=');
      var expected = 'Hello world';
      assert.strictEqual(actual, expected);
    });
  });

  suite('#generateV4UUID', function() {

    test('returns string', function() {
      var actual = keeper.generateV4UUID();
      assert.isString(actual);
    });

    test('returns correct pattern', function() {
      var re = /[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/;
      var actual = keeper.generateV4UUID();
      assert.match(actual, re);
    });
  });

  suite('#randomNumber', function() {

    test('returns number', function() {
      var actual = keeper.randomNumber();
      assert.isNumber(actual);
    });

    test('in no arg range', function() {
      var actual = keeper.randomNumber();
      assert.isTrue(actual >= 0);

      actual = keeper.randomNumber();
      assert.isTrue(actual <= 1);
    });

    test('in one arg range', function() {
      var actual = keeper.randomNumber(10);
      assert.isTrue(actual >= 0);

      actual = keeper.randomNumber(10);
      assert.isTrue(actual <= 10);
    });

    test('in two arg range', function() {
      var actual = keeper.randomNumber(10, 20);
      assert.isTrue(actual >= 10);

      actual = keeper.randomNumber(10, 20);
      assert.isTrue(actual <= 20);
    });
  });

  suite('#randomHex', function() {

    test('throws for unknown number of bytes', function() {
      assert.throws(function() {
        keeper.randomHex();
      });
    });

    test('returns string', function() {
      var actual = keeper.randomHex(16);
      assert.isString(actual);
    });

    test('returns correct pattern', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.randomHex(16);
      assert.match(actual, re);
    });
  });

  suite('#randomBase64', function() {

    test('throws for unknown number of bytes', function() {
      assert.throws(function() {
        keeper.randomBase64();
      });
    });

    test('returns string', function() {
      var actual = keeper.randomBase64(16);
      assert.isString(actual);
    });
  });

  suite('#hmacMd5', function() {

    test('throws for unknown key', function() {
      assert.throws(function() {
        keeper.hmacMd5(null, 'someval');
      });
    });

    test('throws for unknown val', function() {
      assert.throws(function() {
        keeper.hmacMd5('somekey', null);
      });
    });

    test('returns string', function() {
      var actual = keeper.hmacMd5('somekey', 'someval');
      assert.isString(actual);
    });

    test('returns hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.hmacMd5('somekey', 'someval');
      assert.match(actual, re);
    });

    test('returns not hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.hmacMd5('somekey', 'someval', 'base64');
      assert.notMatch(actual, re);
    });
  });

  suite('#hmacSha1', function() {

    test('throws for unknown key', function() {
      assert.throws(function() {
        keeper.hmacSha1(null, 'someval');
      });
    });

    test('throws for unknown val', function() {
      assert.throws(function() {
        keeper.hmacSha1('somekey', null);
      });
    });

    test('returns string', function() {
      var actual = keeper.hmacSha1('somekey', 'someval');
      assert.isString(actual);
    });

    test('returns hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.hmacSha1('somekey', 'someval');
      assert.match(actual, re);
    });

    test('returns not hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.hmacSha1('somekey', 'someval', 'base64');
      assert.notMatch(actual, re);
    });
  });

  suite('#hmacSha256', function() {

    test('throws for unknown key', function() {
      assert.throws(function() {
        keeper.hmacSha256(null, 'someval');
      });
    });

    test('throws for unknown val', function() {
      assert.throws(function() {
        keeper.hmacSha256('somekey', null);
      });
    });

    test('returns string', function() {
      var actual = keeper.hmacSha256('somekey', 'someval');
      assert.isString(actual);
    });

    test('returns hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.hmacSha256('somekey', 'someval');
      assert.match(actual, re);
    });

    test('returns not hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.hmacSha256('somekey', 'someval', 'base64');
      assert.notMatch(actual, re);
    });
  });

  suite('#pbkdf2Hash', function() {

    test('throws for unknown value', function() {
      assert.throws(function() {
        keeper.pbkdf2Hash(null, 'somesalt', 10);
      });
    });

    test('throws for unknown salt', function() {
      assert.throws(function() {
        keeper.pbkdf2Hash('someval', null, 10);
      });
    });

    test('throws for unknown rounds', function() {
      assert.throws(function() {
        keeper.pbkdf2Hash('someval', 'somesalt');
      });
    });

    test('returns string', function() {
      var actual = keeper.pbkdf2Hash('someval', 'somesalt', 10);
      assert.isString(actual);
    });

    test('returns not hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.pbkdf2Hash('someval', 'somesalt', 10);
      assert.notMatch(actual, re);
    });

    test('returns hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.pbkdf2Hash('someval', 'somesalt', 10, 56, 'sha512', 'hex');
      assert.match(actual, re);
    });
  });

  suite('#bcryptHash', function() {

    test('throws for unknown value', function() {
      assert.throws(function() {
        keeper.bcryptHash(null, 5);
      });
    });

    test('throws for unknown rounds', function() {
      assert.throws(function() {
        keeper.bcryptHash('someval');
      });
    });

    test('returns not hex', function() {
      var re = /^[a-f0-9]+$/;
      var actual = keeper.bcryptHash('someval', 5);
      assert.notMatch(actual, re);
    });
  });
});
