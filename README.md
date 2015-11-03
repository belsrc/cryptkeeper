## Cryptkeeper
Some simple wrapper methods to help manage some crypto and crypto-random functions.

### Install
-----------------------------------------------------

Install the package
```bash
npm install cryptkeeper --save
```

Then simply include the module and add it into the application.
```javascript
var cryptkeeper = require('cryptkeeper');
```

### Methods
-----------------------------------------------------

#### #base64Encode(val:Mixed)
Base64 encodes the given value. ```val``` can be a Buffer or a string. If an object or number is provided then it will be stringified before encoding.
```javascript
keeper.base64Encode('Hello world')
// SGVsbG8gd29ybGQ=
```


#### #base64Decode(val:String)
Base64 decodes the given value.
```javascript
keeper.base64Decode('SGVsbG8gd29ybGQ=')
// Hello world
```


#### #generateV4UUID()
Generates a crypto-random V4 UUID.
```javascript
keeper.generateV4UUID()
// f2d54c65-ee01-48dd-8d8c-f46322ac6cf8
```


#### #randomNumber([numOne:Number[, numTwo:Number]])
Generates a crypto-random number. If no parameters are given then the returned number is between 0 and 1. If a parameter is given, the returned number is from 0 to the given number. If two parameters are given, the returned number is between the first number and the second number.
```javascript
keeper.randomNumber()
// 0.30741933521631026

keeper.randomNumber(10)
// 7

keeper.randomNumber(10, 20)
// 19
```


#### #randomHex(numBytes:Number)
Generates a crypto-random hex string that is the given bytes long.
```javascript
keeper.randomHex(16);
// 77a534562141991263d1542546f8920b
```


#### #randomBase64(numBytes:Number)
Generates a crypto-random base 64 string that is the given bytes long.
```javascript
keeper.randomBase64(16);
// mb5cIAM3NEHGd2josTWNnQ==
```


#### #hmacMd5(key:String, val:Mixed[, encoding:String])
Generates a HMAC-MD5 for the given key and value. Returns the hash in the encoding if provided, otherwise, hex.
```javascript
var key = 'foobar';
var body = 'The quick brown fox';

keeper.hmacMd5(key, body);
// ccff21844ddf2e55e8ede3a08a0dc8f2
```


#### #hmacSha1(key:String, val:Mixed[, encoding:String])
Generates a HMAC-SHA1 for the given key and value. Returns the hash in the encoding if provided, otherwise, hex.
```javascript
var key = 'foobar';
var body = 'The quick brown fox';

keeper.hmacSha1(key, body);
// cc05d9cab61c435ddd385cfcb24f1cad24dd3c33
```


#### #hmacSha256(key:String, val:Mixed[, encoding:String])
Generates a HMAC-SHA256 for the given key and value. Returns the hash in the encoding if provided, otherwise, hex.
```javascript
var key = 'foobar';
var body = 'The quick brown fox';

keeper.hmacSha256(key, body);
// c8b664809ce67a2a07754c2ca31f726fb11363d86aab26f094656c58239e2501
```


#### #pbkdf2Hash(val:String, salt:String, rounds:Number[, keylen:Number[, digest:String[, encoding:String]]])
Generates a PBKDF2 hash for the given salt and value with given number of rounds. The key length defaults to 56 if not provided. The digest can be specified and defaults to SHA512. The returned string encoding can also be specified and defaults to Base64.
```javascript
var salt = 'random_salt';
var pass = 'strongPass';
var rounds = 15;

keeper.pbkdf2Hash(pass, salt, rounds);
// LLYkQP/OJXpmEmEN9WTlzbYcJKofsBa+Qh9MHtpVdoB8OLeTKYcVGSK7QZrJcUFrtph3eWTCvDg=

keeper.pbkdf2Hash(pass, salt, rounds, 56, 'md5', 'hex');
// b411a21e7af8bbe603bb358f0d81e53cb4a6f3beb056fc6a6d95fd64df3c29c102048b83761b4b98880469a51b41289c69bb0edcc566bcd1
```


#### #bcryptHash(val:String, rounds:Number)
Generates a bcrypt hash with the given value and number of rounds.
```javascript
var pass = 'strongPass';
var rounds = 12;

keeper.bcryptHash(pass, rounds)
// $2a$12$TMRjxM7AOqgWQBvKwuEAeOpVtBfRz06nU6NeDccb6S/lSML4g/0zG
```


### License
-----------------------------------------------------

Cryptkeeper is licensed under the MIT license.

Copyright (c) 2015 Bryan Kizer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
