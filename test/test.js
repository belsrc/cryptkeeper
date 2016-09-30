'use strict';

const chai   = require('chai');
const chaiAsPromised = require('chai-as-promised');
const assert = chai.assert;

chai.use(chaiAsPromised);

const keeper = require('./../');

suite('Cryptkeeper', () => {

  suite('#base64Encode', () => {

    test('throws for unknown value', () => {
      assert.isRejected(keeper.base64Encode());
    });

    test('returns string for given string', () => {
      assert.eventually.isString(keeper.base64Encode('foo:bar'));
    });

    test('returns string for given object', () => {
      assert.eventually.isString(keeper.base64Encode({foo: 'bar'}));
    });

    test('returns string for given number', () => {
      assert.eventually.isString(keeper.base64Encode(156));
    });

    test('returns string for given Buffer', () => {
      assert.eventually.isString(keeper.base64Encode(new Buffer('foo:bar')));
    });

    test('returns correct value', () => {
      let expected = 'SGVsbG8gd29ybGQ=';
      assert.eventually.strictEqual(keeper.base64Encode('Hello world'), expected);
    });
  });

  suite('#base64Decode', () => {

    test('throws for unknown value', () => {
      assert.isRejected(keeper.base64Decode());
    });

    test('throws for non-string value', () => {
      assert.isRejected(keeper.base64Decode({foo: 'bar'}));
    });

    test('returns string for given string', () => {
      assert.eventually.isString(keeper.base64Decode('SGVsbG8gd29ybGQ='));
    });

    test('returns correct value', () => {
      let expected = 'Hello world';
      assert.eventually.strictEqual(keeper.base64Decode('SGVsbG8gd29ybGQ='), expected);
    });
  });

  suite('#generateV4UUID', () => {

    test('returns string', () => {
      assert.eventually.isString(keeper.generateV4UUID());
    });

    test('returns correct pattern', () => {
      let re = /[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/;
      assert.eventually.match(keeper.generateV4UUID(), re);
    });
  });

  suite('#randomNumber', () => {

    test('returns number', () => {
      assert.eventually.isNumber(keeper.randomNumber());
    });

    test('in no arg range', () => {
      assert.eventually.isAtLeast(keeper.randomNumber(), 0);
      assert.eventually.isAtMost(keeper.randomNumber(), 1);
    });

    test('in one arg range', () => {
      assert.eventually.isAtLeast(keeper.randomNumber(10), 0);
      assert.eventually.isAtMost(keeper.randomNumber(10), 10);
    });

    test('in two arg range', () => {
      assert.eventually.isAtLeast(keeper.randomNumber(10, 20), 10);
      assert.eventually.isAtMost(keeper.randomNumber(10, 20), 20);
    });
  });

  suite('#randomHex', () => {

    test('throws for unknown number of bytes', () => {
      assert.isRejected(keeper.randomHex());
    });

    test('returns string', () => {
      assert.eventually.isString(keeper.randomHex(16));
    });

    test('returns correct pattern', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.match(keeper.randomHex(16), re);
    });
  });

  suite('#randomBase64', () => {

    test('throws for unknown number of bytes', () => {
      assert.isRejected(keeper.randomBase64());
    });

    test('returns string', () => {
      assert.eventually.isString(keeper.randomBase64(16));
    });
  });

  suite('#hmacMd5', () => {

    test('throws for unknown key', () => {
      assert.isRejected(keeper.hmacMd5(null, 'someval'));
    });

    test('throws for unknown val', () => {
      assert.isRejected(keeper.hmacMd5('somekey', null));
    });

    test('returns string', () => {
      assert.eventually.isString(keeper.hmacMd5('somekey', 'someval'));
    });

    test('returns hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.match(keeper.hmacMd5('somekey', 'someval'), re);
    });

    test('returns not hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.notMatch(keeper.hmacMd5('somekey', 'someval', 'base64'), re);
    });
  });

  suite('#hmacSha1', () => {

    test('throws for unknown key', () => {
      assert.isRejected(keeper.hmacSha1(null, 'someval'));
    });

    test('throws for unknown val', () => {
      assert.isRejected(keeper.hmacSha1('somekey', null));
    });

    test('returns string', () => {
      assert.eventually.isString(keeper.hmacSha1('somekey', 'someval'));
    });

    test('returns hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.match(keeper.hmacSha1('somekey', 'someval'), re);
    });

    test('returns not hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.notMatch(keeper.hmacSha1('somekey', 'someval', 'base64'), re);
    });
  });

  suite('#hmacSha256', () => {

    test('throws for unknown key', () => {
      assert.isRejected(keeper.hmacSha256(null, 'someval'));
    });

    test('throws for unknown val', () => {
      assert.isRejected(keeper.hmacSha256('somekey', null));
    });

    test('returns string', () => {
      assert.eventually.isString(keeper.hmacSha256('somekey', 'someval'));
    });

    test('returns hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.match(keeper.hmacSha256('somekey', 'someval'), re);
    });

    test('returns not hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.notMatch(keeper.hmacSha256('somekey', 'someval', 'base64'), re);
    });
  });

  suite('#pbkdf2Hash', () => {

    test('throws for unknown value', () => {
      assert.isRejected(keeper.pbkdf2Hash(null, 'somesalt', 10));
    });

    test('throws for unknown salt', () => {
      assert.isRejected(keeper.pbkdf2Hash('someval', null, 10));
    });

    test('throws for unknown rounds', () => {
      assert.isRejected(keeper.pbkdf2Hash('someval', 'somesalt'));
    });

    test('returns string', () => {
      assert.eventually.isString(keeper.pbkdf2Hash('someval', 'somesalt', 10));
    });

    test('returns not hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.notMatch(keeper.pbkdf2Hash('someval', 'somesalt', 10), re);
    });

    test('returns hex', () => {
      let re = /^[a-f0-9]+$/;
      assert.eventually.match(keeper.pbkdf2Hash('someval', 'somesalt', 10, 56, 'sha512', 'hex'), re);
    });
  });

  suite('#bcryptHash', () => {

    test('throws for unknown value', () => {
      assert.isRejected(keeper.bcryptHash(null, 5));
    });

    test('throws for unknown rounds', () => {
      assert.isRejected(keeper.bcryptHash('someval'));
    });

    test('returns correct hash', () => {
      let expected = '$2a$10$fWyqxuj6NWll9sokndTVoeakdZhyhBDkucLHhKDdEL0wqL1YkiGou';
      assert.eventually.strictEqual(keeper.bcryptHash('unit&test', 10), expected);
    });
  });

  suite('#bcryptCompare', () => {

    test('throws for unknown given', () => {
      assert.isRejected(keeper.bcryptCompare(null, ''));
    });

    test('throws for unknown hash', () => {
      assert.isRejected(keeper.bcryptCompare('someval'));
    });

    test('returns true for match', () => {
      let hash = '$2a$10$fWyqxuj6NWll9sokndTVoeakdZhyhBDkucLHhKDdEL0wqL1YkiGou';
      let given = 'unit&test';
      assert.eventually.isTrue(keeper.bcryptCompare(given, hash));
    });

    test('returns false for mismatch', () => {
      let hash = '$2a$10$fWyqxuj6NWll9sokndTVoeakdZhyhBDkucLHhKDdEL0wqL1YkiGou';
      let given = 'test&unit';
      assert.eventually.isTrue(keeper.bcryptCompare(given, hash));
    });
  });

  suite('#argonHash', () => {

    test('throws for unknown value', () => {
      assert.isRejected(keeper.argonHash());
    });

    test('returns correct hash for default options', () => {
      let expected = '$argon2i$v=19$m=4096,t=3,p=1$/u30wNNYOfYADLFWn+PMnQ$6vbaaXlHb2uC2jxTX7RsAJivyEIfnT0sC2w3kbzupQQ';
      assert.eventually.strictEqual(keeper.argonHash('unit&test'), expected);
    });

    test('returns correct hash for given options', () => {
      let expected = '$argon2d$v=19$m=8192,t=4,p=2$LaxrvchRgoqf0WAiaxB5ZQ$0u9pkixo5S1SznL/k8hxc95xa1InoopKhCiPJ1izlTw';
      let options = { timeCost: 4, memoryCost: 13, parallelism: 2, argon2d: true };
      assert.eventually.strictEqual(keeper.argonHash('unit&test'), expected);
    });
  });

  suite('#argonCompare', () => {

    test('throws for unknown given', () => {
      assert.isRejected(keeper.argonCompare(null, ''));
    });

    test('throws for unknown hash', () => {
      assert.isRejected(keeper.argonCompare('someval'));
    });

    test('returns true for match', () => {
      let hash = '$argon2i$v=19$m=4096,t=3,p=1$/u30wNNYOfYADLFWn+PMnQ$6vbaaXlHb2uC2jxTX7RsAJivyEIfnT0sC2w3kbzupQQ';
      let hash2 = '$argon2d$v=19$m=8192,t=4,p=2$LaxrvchRgoqf0WAiaxB5ZQ$0u9pkixo5S1SznL/k8hxc95xa1InoopKhCiPJ1izlTw';
      let given = 'unit&test';
      assert.eventually.isTrue(keeper.argonCompare(given, hash));
      assert.eventually.isTrue(keeper.argonCompare(given, hash2));
    });

    test('returns false for mismatch', () => {
      let hash = '$argon2i$v=19$m=4096,t=3,p=1$/u30wNNYOfYADLFWn+PMnQ$6vbaaXlHb2uC2jxTX7RsAJivyEIfnT0sC2w3kbzupQQ';
      let hash2 = '$argon2d$v=19$m=8192,t=4,p=2$LaxrvchRgoqf0WAiaxB5ZQ$0u9pkixo5S1SznL/k8hxc95xa1InoopKhCiPJ1izlTw';
      let given = 'test&unit';
      assert.eventually.isTrue(keeper.argonCompare(given, hash));
      assert.eventually.isTrue(keeper.argonCompare(given, hash2));
    });
  });
});
