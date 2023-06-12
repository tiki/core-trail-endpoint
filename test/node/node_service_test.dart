/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:sqlite3/common.dart';
import 'package:sqlite3/sqlite3.dart';
import 'package:test/test.dart';
import 'package:tiki_trail/node/backup/backup_service.dart';
import 'package:tiki_trail/node/block/block_model.dart';
import 'package:tiki_trail/node/block/block_repository.dart';
import 'package:tiki_trail/node/block/block_service.dart';
import 'package:tiki_trail/node/key/key_model.dart';
import 'package:tiki_trail/node/key/key_service.dart';
import 'package:tiki_trail/node/node_service.dart';
import 'package:tiki_trail/node/transaction/transaction_model.dart';
import 'package:tiki_trail/node/transaction/transaction_repository.dart';
import 'package:tiki_trail/node/transaction/transaction_service.dart';
import 'package:tiki_trail/utils/bytes.dart';
import 'package:tiki_trail/utils/rsa/rsa_public_key.dart';
import 'package:uuid/uuid.dart';

import '../in_mem.dart';

void main() {
  group('Node tests', () {
    test('Init - No Primary - Success ', () async {
      InMemL0Storage backupClient = InMemL0Storage();
      CommonDatabase database = sqlite3.openInMemory();
      KeyService keyService = KeyService(InMemKeyStorage());
      KeyModel primaryKey = await keyService.create();
      NodeService node = NodeService()
        ..blockInterval = const Duration(minutes: 1)
        ..maxTransactions = 200
        ..transactionService = TransactionService(database)
        ..blockService = BlockService(database)
        ..primaryKey = primaryKey;
      node.backupService =
          BackupService(backupClient, database, primaryKey, node.getBlock);

      Uint8List address = Bytes.base64UrlDecode(node.address);
      Uint8List? publicKey = await backupClient
          .read('${Bytes.base64UrlEncode(address)}/public.key');

      expect(publicKey != null, true);
      expect(Digest("SHA3-256").process(publicKey!), address);

      KeyModel? key = await keyService.get(primaryKey.id);
      RsaPublicKey rsaPublicKey = RsaPublicKey.decode(base64.encode(publicKey));

      expect(key != null, true);
      expect(rsaPublicKey, key?.privateKey.public);

      await Future.delayed(const Duration(seconds: 3));

      BlockRepository blockRepository = BlockRepository(database);
      TransactionRepository transactionRepository =
          TransactionRepository(database);

      BlockModel? last = blockRepository.getLast();
      List<TransactionModel> pending = transactionRepository.getByBlockId(null);

      expect(last == null, true);
      expect(pending.isEmpty, true);
    });

    test('Write - Success ', () async {
      NodeService node = await InMemBuilders.nodeService();
      TransactionModel tx =
          await node.write(Uint8List.fromList(utf8.encode(const Uuid().v4())));

      expect(tx.id != null, true);
      expect(tx.userSignature != null, true);

      TransactionRepository transactionRepository =
          TransactionRepository(node.database);
      List<TransactionModel> pending = transactionRepository.getByBlockId(null);
      expect(pending.length, 1);

      await Future.delayed(const Duration(seconds: 3));

      BlockRepository blockRepository = BlockRepository(node.database);
      BlockModel? last = blockRepository.getLast();
      expect(last != null, true);
      expect(last?.id != null, true);

      List<TransactionModel> txns =
          transactionRepository.getByBlockId(last!.id);
      pending = transactionRepository.getByBlockId(null);

      expect(txns.length, 1);
      expect(txns.elementAt(0).id, tx.id);
      expect(pending.length, 0);
    });

    test('Re-init - With Primary - Success ', () async {
      NodeService node = await InMemBuilders.nodeService();
      String address = node.address;
      expect(node.address, address);
    });

    test('Re-init - Invalid Address - Success ', () async {
      NodeService node = await InMemBuilders.nodeService();
      String address = const Uuid().v4();
      String address2 = node.address;
      expect(address != address2, true);
    });
  });
}
