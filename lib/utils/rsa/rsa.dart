/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */
/// Helper functions for asymmetric keys in RSA
/// {@category Utils}
library rsa;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../isolate.dart';
import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

typedef RsaKeyPair = AsymmetricKeyPair<CryptoRSAPublicKey, CryptoRSAPrivateKey>;

/// Generates a [RsaKeyPair] a [secureRandom]
RsaKeyPair generate() {
  final keyGen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64),
        secureRandom()));

  AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = keyGen.generateKeyPair();
  RSAPublicKey publicKey = keyPair.publicKey as RSAPublicKey;
  RSAPrivateKey privateKey = keyPair.privateKey as RSAPrivateKey;

  return RsaKeyPair(
      CryptoRSAPublicKey(publicKey.modulus!, publicKey.publicExponent!),
      CryptoRSAPrivateKey(privateKey.modulus!, privateKey.privateExponent!,
          privateKey.p, privateKey.q));
}

Future<RsaKeyPair> generateAsync() =>
    compute((_) => generate(), "").then((keyPair) => keyPair);

Uint8List encrypt(CryptoRSAPublicKey key, Uint8List plaintext) {
  final encryptor = OAEPEncoding(RSAEngine())
    ..init(true, PublicKeyParameter<RSAPublicKey>(key));
  return processInBlocks(encryptor, plaintext);
}

Future<Map<String, Uint8List>> encryptBulk(
    CryptoRSAPublicKey key, Map<String, Uint8List> req) {
  Map<String, String> q =
      req.map((key, value) => MapEntry(key, base64.encode(value)));
  q['CRYPTORSAPUBLICKEY'] = key.encode();
  return compute((Map<String, String> q) {
    CryptoRSAPublicKey aes =
        CryptoRSAPublicKey.decode(q.remove('CRYPTORSAPUBLICKEY')!);
    return q
        .map((key, value) => MapEntry(key, encrypt(aes, base64.decode(value))));
  }, q)
      .then((rsp) => rsp);
}

Future<Uint8List> encryptAsync(CryptoRSAPublicKey key, Uint8List plaintext) {
  Map<String, String> q = {};
  q['plaintext'] = base64.encode(plaintext);
  q['key'] = key.encode();
  return compute(
          (Map<String, String> q) => encrypt(
              CryptoRSAPublicKey.decode(q['key']!),
              base64.decode(q['plaintext']!)),
          q)
      .then((ciphertext) => ciphertext);
}

Uint8List decrypt(CryptoRSAPrivateKey key, Uint8List ciphertext) {
  final decryptor = OAEPEncoding(RSAEngine())
    ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
  return processInBlocks(decryptor, ciphertext);
}

Future<Uint8List> decryptAsync(CryptoRSAPrivateKey key, Uint8List ciphertext) {
  Map<String, String> q = {};
  q['ciphertext'] = base64.encode(ciphertext);
  q['key'] = key.encode();
  return compute(
          (Map<String, String> q) => decrypt(
              CryptoRSAPrivateKey.decode(q['key']!),
              base64.decode(q['ciphertext']!)),
          q)
      .then((plaintext) => plaintext);
}

Uint8List sign(CryptoRSAPrivateKey key, Uint8List message) {
  RSASigner signer = RSASigner(SHA256Digest(), '0609608648016503040201');
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(key));
  RSASignature signature = signer.generateSignature(message);
  return signature.bytes;
}

Future<Map<String, Uint8List>> signBulk(
    CryptoRSAPrivateKey key, Map<String, Uint8List> req) {
  Map<String, String> q =
      req.map((key, value) => MapEntry(key, base64.encode(value)));
  q['CRYPTORSAPRIVATEKEY'] = key.encode();
  return compute((Map<String, String> q) {
    CryptoRSAPrivateKey aes =
        CryptoRSAPrivateKey.decode(q.remove('CRYPTORSAPRIVATEKEY')!);
    return q
        .map((key, value) => MapEntry(key, sign(aes, base64.decode(value))));
  }, q)
      .then((rsp) => rsp);
}

Future<Uint8List> signAsync(CryptoRSAPrivateKey key, Uint8List message) {
  Map<String, String> q = {};
  q['message'] = base64.encode(message);
  q['key'] = key.encode();
  return compute(
          (Map<String, String> q) => sign(CryptoRSAPrivateKey.decode(q['key']!),
              base64.decode(q['message']!)),
          q)
      .then((signature) => signature);
}

bool verify(CryptoRSAPublicKey key, Uint8List message, Uint8List signature) {
  RSASignature rsaSignature = RSASignature(signature);
  final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');
  verifier.init(false, PublicKeyParameter<RSAPublicKey>(key));
  try {
    return verifier.verifySignature(message, rsaSignature);
  } on ArgumentError {
    return false;
  }
}

Future<bool> verifyAsync(
    CryptoRSAPublicKey key, Uint8List message, Uint8List signature) {
  Map<String, String> q = {};
  q['message'] = base64.encode(message);
  q['signature'] = base64.encode(signature);
  q['key'] = key.encode();
  return compute(
          (Map<String, String> q) => verify(
              CryptoRSAPublicKey.decode(q['key']!),
              base64.decode(q['message']!),
              base64.decode(q['signature']!)),
          q)
      .then((isVerified) => isVerified);
}

Future<bool> verifyAll(CryptoRSAPublicKey key, Map<Uint8List, Uint8List> req) {
  Map<String, String> q = req
      .map((key, value) => MapEntry(base64.encode(key), base64.encode(value)));
  q['CRYPTORSAPUBLICKEY'] = key.encode();
  return compute((Map<String, String> q) {
    CryptoRSAPublicKey aes =
        CryptoRSAPublicKey.decode(q.remove('CRYPTORSAPUBLICKEY')!);
    for (MapEntry<String, String> entry in q.entries) {
      if (!verify(aes, base64.decode(entry.key), base64.decode(entry.value))) {
        return false;
      }
    }
    return true;
  }, q)
      .then((isVerified) => isVerified);
}

FortunaRandom secureRandom() {
  var secureRandom = FortunaRandom();
  var random = Random.secure();
  final seeds = <int>[];
  for (int i = 0; i < 32; i++) {
    seeds.add(random.nextInt(255));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
  return secureRandom;
}

Uint8List processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
  final numBlocks = input.length ~/ engine.inputBlockSize +
      ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

  final output = Uint8List(numBlocks * engine.outputBlockSize);

  var inputOffset = 0;
  var outputOffset = 0;
  while (inputOffset < input.length) {
    final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
        ? engine.inputBlockSize
        : input.length - inputOffset;

    outputOffset += engine.processBlock(
        input, inputOffset, chunkSize, output, outputOffset);

    inputOffset += chunkSize;
  }

  return (output.length == outputOffset)
      ? output
      : output.sublist(0, outputOffset);
}