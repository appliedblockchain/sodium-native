var tape = require('tape')
var sodium = require('..')

tape('crypto_vrf_keypair', function (t) {
  var pk = Buffer.alloc(sodium.crypto_vrf_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_vrf_SECRETKEYBYTES)

  sodium.crypto_vrf_keypair(pk, sk)

  t.notEqual(pk, Buffer.alloc(pk.length), 'made public key')
  t.notEqual(sk, Buffer.alloc(sk.length), 'made secret key')

  t.throws(function () {
    sodium.crypto_vrf_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_vrf_keypair(Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  t.end()
})

tape('crypto_vrf_keypair_from_seed', function (t) {
  var pk = Buffer.alloc(sodium.crypto_vrf_PUBLICKEYBYTES)
  var sk = Buffer.alloc(sodium.crypto_vrf_SECRETKEYBYTES)
  var seed = Buffer.alloc(sodium.crypto_vrf_SEEDBYTES)

  sodium.crypto_vrf_keypair_from_seed(pk, sk, seed)

  t.notEqual(pk, Buffer.alloc(pk.length), 'made public key')
  t.notEqual(sk, Buffer.alloc(sk.length), 'made secret key')

  t.throws(function () {
    sodium.crypto_sign_keypair()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_sign_keypair(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  t.end()
})

tape('crypto_vrf_sk_to_pk', function (t) {
  var pk = Buffer.alloc(sodium.crypto_vrf_PUBLICKEYBYTES)
  var skpk = Buffer.alloc(sodium.crypto_vrf_SECRETKEYBYTES)

  sodium.crypto_vrf_sk_to_pk(pk, skpk)

  t.notEqual(pk, Buffer.alloc(pk.length), 'made public key')
  t.notEqual(skpk, Buffer.alloc(skpk.length), 'made secret key')

  t.throws(function () {
    sodium.crypto_vrf_sk_to_pk()
  }, 'should validate input')

  t.throws(function () {
    sodium.crypto_vrf_sk_to_pk(Buffer.alloc(0), Buffer.alloc(0))
  }, 'should validate input length')

  t.end()
})

// tape('sn_crypto_vrf_prove', function (t) {
//   var pk = Buffer.alloc(sodium.crypto_vrf_PUBLICKEYBYTES)
//   var skpk = Buffer.alloc(sodium.crypto_vrf_SECRETKEYBYTES)
//   var proof = Buffer.alloc(sodium.crypto_vrf_PROOFBYTES)
//   var msg = Buffer.from('Hello, World!')

//   sodium.crypto_vrf_keypair(pk, skpk)

//   t.ok(sodium.crypto_vrf_prove(proof, skpk, msg))

//   t.notEqual(proof, Buffer.alloc(proof.length), 'made proof')

//   t.throws(function () {
//     sodium.crypto_vrf_prove()
//   }, 'should validate input')

//   t.throws(function () {
//     sodium.crypto_vrf_prove(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0))
//   }, 'should validate input length')

//   t.end()
// })
