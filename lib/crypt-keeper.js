'use strict';

const Promise = require('bluebird');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

function hmac(algorithm, key, val, encoding) {
  encoding = encoding || 'hex';

  return new Promise((resolve, reject) => {
    if(typeof val !== 'string') {
      val = JSON.stringify(val);
    }

    let hash = crypto
      .createHmac(algorithm, key)
      .update(val)
      .digest(encoding);

    return resolve(hash);
  });
}

class CryptKeeper {
  /**
   * Base 64 encodes the given value.
   * @param  {Mixed}   val  The value to base 64 encode.
   * @return {Promise}
   */
  base64Encode(val) {
    if(!val) {
      return Promise.reject(new Error('val can not be null'));
    }

    return new Promise((resolve, reject) => {
      let buff;

      if(val instanceof Buffer) {
        buff = val;
      }
      else {
        if(typeof val !== 'string') {
          val = JSON.stringify(val);
        }

        buff = new Buffer(val);
      }

      return resolve(buff.toString('base64'));
    });
  }

  /**
   * Base 64 decodes the given value.
   * @param  {Mixed}   val  The value to base 64 decode.
   * @return {Promise}
   */
  base64Decode(val) {
    if(!val) {
      return Promise.reject(new Error('val can not be null'));
    }

    if(typeof val !== 'string') {
      return Promise.reject(new Error('value must be a string'));
    }

    return Promise.resolve(new Buffer(val, 'base64').toString('ascii'));
  }

  /**
   * Generates a RFC v4 UUID.
   * @return {Promise}
   */
  generateV4UUID() {
    const self = this;

    return new Promise(function(resolve, reject) {
      return resolve(('' + 1e7 + -1e3 + -4e3 + -8e3 + -1e11).replace(/1|0/g, () => {
        return (0 | self.randomNumber() * 16).toString(16);
      }));
    });
  }

  /**
   * Generates a random number.
   * @param  {Number}  numOne  The upper bound if a single number is given, otherwise, the lower bound.
   * @param  {Number}  numTwo  The upper bound if both numbers are supplied.
   * @return {Promise}
   */
  randomNumber(numOne, numTwo) {
    let buffer = crypto.randomBytes(8);
    let hex = buffer.toString('hex');
    let integer = parseInt(hex, 16);
    let random = integer / 0xffffffffffffffff;

    return new Promise((resolve, reject) => {
      if(!numOne){
        return resolve(random);
      }

      // Only single number given.
      if(!numTwo) {
        numTwo = numOne;
        numOne = 0;
      }

      // If second number is smaller, switch them
      if(numTwo && numTwo > numOne) {
        let tmp = numOne;
        numOne = numTwo;
        numTwo = tmp;
      }

      return resolve(Math.floor(random * (numOne - numTwo + 1)) + numTwo);
    });
  }

  /**
   * Generates a random hex string.
   * @param  {Number}  numBytes  The number of bytes.
   * @return {Promise}
   */
  randomHex(numBytes) {
    if(!numBytes) {
      return Promise.reject(new Error('number of bytes can not be null'));
    }

    return Promise.resolve(crypto.randomBytes(numBytes).toString('hex'));
  }

  /**
   * Generates a random base64 string.
   * @param  {Number}  numBytes  The number of bytes.
   * @return {Promise}
   */
  randomBase64(numBytes) {
    if(!numBytes) {
      return Promise.reject(new Error('number of bytes can not be null'));
    }

    return Promise.resolve(crypto.randomBytes(numBytes).toString('base64'));
  }

  /**
   * Creates a MD5 HMAC hash.
   * @param  {String}  key       The HMAC key string.
   * @param  {String}  val       The value to hash.
   * @param  {String}  encoding  The returned encoding type, defaults to hex.
   * @return {Promise}
   */
  hmacMd5(key, val, encoding) {
    if(!key) {
      return Promise.reject(new Error('key can not be null'));
    }

    if(!val) {
      return Promise.reject(new Error('value can not be null'));
    }

    return hmac('md5', key, val, encoding);
  }

  /**
   * Creates a SHA1 HMAC hash.
   * @param  {String}  key       The HMAC key string.
   * @param  {String}  val       The value to hash.
   * @param  {String}  encoding  The returned encoding type, defaults to hex.
   * @return {Promise}
   */
  hmacSha1(key, val, encoding) {
    if(!key) {
      return Promise.reject(new Error('key can not be null'));
    }

    if(!val) {
      return Promise.reject(new Error('value can not be null'));
    }

    return hmac('sha1', key, val, encoding);
  }

  /**
   * Creates a SHA256 HMAC hash.
   * @param  {String}  key       The HMAC key string.
   * @param  {String}  val       The value to hash.
   * @param  {String}  encoding  The returned encoding type, defaults to hex.
   * @return {Promise}
   */
  hmacSha256(key, val, encoding) {
    if(!key) {
      return Promise.reject(new Error('key can not be null'));
    }

    if(!val) {
      return Promise.reject(new Error('value can not be null'));
    }

    return hmac('sha256', key, val, encoding);
  }

  /**
   * Hashes the supplied value using PBKDF2.
   * @param  {String}  val       The value to hash.
   * @param  {String}  salt      The salt string.
   * @param  {Number}  rounds    The encryption work factor.
   * @param  {Number}  keylen    The key length.
   * @param  {String}  digest    The hashing digest, defaults to SHA512.
   * @param  {String}  encoding  The returned encoding type, defaults to base 64.
   * @return {Promise}
   */
  pbkdf2Hash(val, salt, rounds, keylen, digest, encoding) {
    if(!val) {
      return Promise.reject(new Error('value can not be null'));
    }

    if(!salt) {
      return Promise.reject(new Error('salt can not be null'));
    }

    if(!rounds) {
      return Promise.reject(new Error('rounds can not be null'));
    }

    return new Promise((resolve, reject) => {
      keylen = keylen || 56;
      digest = digest || 'sha512';
      encoding = encoding || 'base64';

      let iterations = Math.pow(2, rounds);
      let hash = crypto.pbkdf2Sync(val, salt, iterations, keylen, digest).toString(encoding);

      return resolve(hash);
    });
  }

  /**
   * Hashes the supplied value using Bcrypt.
   * @param  {String}  val     The value to hash.
   * @param  {Number}  rounds  The encryption work factor.
   * @return {Promise}
   */
  bcryptHash(val, rounds) {
    if(!val) {
      return Promise.reject(new Error('value can not be null'));
    }

    if(!rounds) {
      return Promise.reject(new Error('rounds can not be null'));
    }

    return new Promise((resolve, reject) => {
      bcrypt.hash(val, rounds, (error, hash) => {
        if(error) {
          return reject(error);
        }

        return resolve(hash);
      });
    });
  }

  /**
   * Compares the given text to the expected hash.
   * @param {String}   given  The given string.
   * @param {String}   hash   The expected hash.
   * @return {Promise}
   */
  bcryptCompare(given, hash) {
    if(!given) {
      return Promise.reject(new Error('given can not be null'));
    }

    if(!hash) {
      return Promise.reject(new Error('hash can not be null'));
    }

    return new Promise(function(resolve, reject) {
      bcrypt.compare(given, hash, function(error, result) {
        if(error) {
          return reject(error);
        }

        return resolve(result);
      });
    });
  }

  /**
   * Hashes the supplied value using Argon2.
   * @param  {String}  val      The value to hash.
   * @param  {Object}  options  Object containing argon2 options.
   * @return {Promise}
   */
  argonHash(val, options) {
    if(!val) {
      return Promise.reject(new Error('value can not be null'));
    }

    options = options || {};

    return argon2
      .generateSalt()
      .then(salt => {
        return argon2.hash(val, salt, options);
      });
  }

  /**
   * Compares the given text to the expected hash.
   * @param {String}   given  The given string.
   * @param {String}   hash   The expected hash.
   * @return {Promise}
   */
  argonCompare(given, hash) {
    if(!given) {
      return Promise.reject(new Error('given can not be null'));
    }

    if(!hash) {
      return Promise.reject(new Error('hash can not be null'));
    }

    return argon2.verify(hash, given);
  }
}

module.exports = new CryptKeeper();
