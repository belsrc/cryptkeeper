
var keeper = require('./');

var salt = 'random_salt';
var pass = 'strongPass';
var rounds = 12;
//console.log(keeper.pbkdf2Hash(pass, salt, rounds));

//(val, salt, rounds, keylen, digest, encoding)
console.log(keeper.bcryptHash(pass, rounds));
