'use strict';

var crypto = require('crypto');
var bcrypt = require('bcrypt');


var hmac = function(algorithm, key, val, encoding) {
  encoding = encoding || 'hex';

  if(typeof val !== 'string') {
    val = JSON.stringify(val);
  }

  return crypto
    .createHmac(algorithm, key)
    .update(val)
    .digest(encoding);
};


var CryptKeeper = function() {};


/**
 * Base 64 encodes the given value.
 * @param  {Mixed}  val The value to base 64 encode.
 * @return {String}
 */
CryptKeeper.prototype.base64Encode = function(val) {
  var buff;

  if(val instanceof Buffer) {
    buff = val;
  }
  else {
    if(typeof val !== 'string') {
      val = JSON.stringify(val);
    }
    buff = new Buffer(val);
  }

  return buff.toString('base64');
};


/**
 * Base 64 decodes the given value.
 * @param  {Mixed}  val The value to base 64 decode.
 * @return {String}
 */
CryptKeeper.prototype.base64Decode = function(val) {
  return new Buffer(val, 'base64').toString('ascii');
};


/**
 * Generates a RFC v4 UUID.
 * @return {String}
 */
CryptKeeper.prototype.generateV4UUID = function() {
  var _this = this;
  return('' + 1e7 + -1e3 + -4e3 + -8e3 + -1e11).replace(/1|0/g, function() {
    return(0 | _this.randomNumber() * 16).toString(16);
  });
};


/**
 * Generates a random number.
 * @param  {Number} numOne The upper bound if a single number is given, otherwise, the lower bound.
 * @param  {Number} numTwo The upper bound if both numbers are supplied.
 * @return {Number}
 */
CryptKeeper.prototype.randomNumber = function(numOne, numTwo) {
  var buffer = crypto.randomBytes(8);
  var hex = buffer.toString('hex');
  var integer = parseInt(hex, 16);
  var random = integer / 0xffffffffffffffff;

  if(!numOne){
    return random;
  }
  else {

    // Only single number given.
    if(!numTwo) {
      numTwo = numOne;
      numOne = 0;
    }

    // If second number is smaller, switch them
    if(numTwo && numTwo > numOne) {
      var tmp = numOne;
      numOne = numTwo;
      numTwo = tmp;
    }

    return Math.floor(random * (numOne - numTwo + 1)) + numTwo;
  }
};


/**
 * Generates a random hex string.
 * @param  {Number}  numBytes  The number of bytes.
 * @return {String}
 */
CryptKeeper.prototype.randomHex = function(numBytes) {
  return crypto.randomBytes(numBytes).toString('hex');
};


/**
 * Generates a random base64 string.
 * @param  {Number}  numBytes  The number of bytes.
 * @return {String}
 */
CryptKeeper.prototype.randomBase64 = function(numBytes) {
  return crypto.randomBytes(numBytes).toString('base64');
};


/**
 * Creates a MD5 HMAC hash.
 * @param  {String} key      The HMAC key string.
 * @param  {String} val      The value to hash.
 * @param  {String} encoding The returned encoding type, defaults to hex.
 * @return {String}
 */
CryptKeeper.prototype.hmacMd5 = function(key, val, encoding) {
  return hmac('md5', key, val, encoding);
};


/**
 * Creates a SHA1 HMAC hash.
 * @param  {String} key      The HMAC key string.
 * @param  {String} val      The value to hash.
 * @param  {String} encoding The returned encoding type, defaults to hex.
 * @return {String}
 */
CryptKeeper.prototype.hmacSha1 = function(key, val, encoding) {
  return hmac('sha1', key, val, encoding);
};


/**
 * Creates a SHA256 HMAC hash.
 * @param  {String} key      The HMAC key string.
 * @param  {String} val      The value to hash.
 * @param  {String} encoding The returned encoding type, defaults to hex.
 * @return {String}
 */
CryptKeeper.prototype.hmacSha256 = function(key, val, encoding) {
  return hmac('sha256', key, val, encoding);
};


/**
 * Hashes the supplied value using PBKDF2.
 * @param  {String} val      The value to hash.
 * @param  {String} salt     The salt string.
 * @param  {Number} rounds   The encryption work factor.
 * @param  {Number} keylen   The key length.
 * @param  {String} digest   The hashing digest, defaults to SHA512.
 * @param  {String} encoding The returned encoding type, defaults to base 64.
 * @return {String}
 */
CryptKeeper.prototype.pbkdf2Hash = function(val, salt, rounds, keylen, digest, encoding) {
  encoding = encoding || 'base64';
  keylen = keylen || 56;
  digest = digest || 'sha512';
  var iterations = Math.pow(2, rounds);
  return crypto.pbkdf2Sync(val, salt, iterations, keylen, digest).toString(encoding);
};


/**
 * Hashes the supplied value using Bcrypt.
 * @param  {String} val   The value to hash.
 * @param  {Number} rounds The encryption work factor.
 * @return {String}
 */
CryptKeeper.prototype.bcryptHash = function(val, rounds) {
  return bcrypt.hashSync(val, rounds);
};


module.exports = new CryptKeeper();
