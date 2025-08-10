# Copyright (c) 2025 The Evrmore Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import EvrmoreTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class P2AHTest(EvrmoreTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        # Mine some blocks to fund the wallet
        node.generate(101)

        # Issue a root asset which creates an owner token ASSET!
        addr_issue = node.getnewaddress()
        node.issue("CORP", 1000, addr_issue, addr_issue, 0, 0, False)
        self.sync_all()

        # Verify we own CORP!
        balances = node.listmyassets()
        assert "CORP!" in balances
        assert_equal(int(balances["CORP!"]), 1)

        # Derive P2AH address for CORP!
        res = node.getp2ahaddress("CORP!")
        a_addr = res["address"]
        assert a_addr.startswith("A")

        # Send EVR to A-addr
        txid_fund = node.sendtoaddress(a_addr, 5)
        node.generate(1)
        self.sync_all()

        # Find the specific UTXO to the A-addr
        utxos = node.listunspent()
        a_utxos = [u for u in utxos if u.get("address") == a_addr]
        assert len(a_utxos) >= 1
        a_utxo = a_utxos[0]

        # Attempt raw spend of the P2AH UTXO without including CORP! owner transfer - expect reject
        dest = node.getnewaddress()
        inputs = [{"txid": a_utxo["txid"], "vout": a_utxo["vout"]}]
        outputs = {dest: 4.999}  # leave fee
        raw = node.createrawtransaction(inputs, outputs)
        signed = node.signrawtransaction(raw)
        assert signed["complete"]
        assert_raises_rpc_error(-26, "bad-txns-p2ah-missing-owner-asset", node.sendrawtransaction, signed["hex"])

        # Now force wallet spend of that P2AH UTXO by locking all others
        for u in utxos:
            if not (u["txid"] == a_utxo["txid"] and u["vout"] == a_utxo["vout"]):
                node.lockunspent(False, [{"txid": u["txid"], "vout": u["vout"]}])

        # Wallet-driven send should auto-include CORP! owner transfer and succeed
        dest2 = node.getnewaddress()
        txid_spend = node.sendtoaddress(dest2, 4.5)
        node.generate(1)
        self.sync_all()

        # Decode and verify owner asset transfer in outputs
        decoded = node.getrawtransaction(txid_spend, 1)
        has_owner = False
        for vout in decoded["vout"]:
            asset = vout.get("asset")
            if isinstance(asset, dict) and asset.get("name") == "CORP!":
                has_owner = True
                break
        assert has_owner, "Expected owner asset transfer CORP! in transaction outputs"

        # Test message signing
        sig = node.signmessagep2ah("CORP!", "hello world")
        ok = node.verifymessagep2ah("CORP!", sig["address"], sig["signature"])
        assert ok

        # Now test stacked/multisig P2AH
        # Create another owner asset
        node.issue("ALLY", 1000, addr_issue, addr_issue, 0, 0, False)
        node.generate(1)
        assert "ALLY!" in node.listmyassets()

        # Build P2AH requiring either CORP! or ALLY! with OP_TRUE payload
        res2 = node.createp2ahaddress(["CORP!", "ALLY!"])
        a2 = res2["address"]
        txid2 = node.sendtoaddress(a2, 3)
        node.generate(1)

        # Try to spend without owner: should reject
        utxos = node.listunspent()
        a2utxo = next(u for u in utxos if u.get("address") == a2)
        raw2 = node.createrawtransaction([{"txid": a2utxo["txid"], "vout": a2utxo["vout"]}], {node.getnewaddress(): 2.999})
        signed2 = node.signrawtransaction(raw2)
        assert_raises_rpc_error(-26, "bad-txns-p2ah-missing-owner-asset", node.sendrawtransaction, signed2["hex"])

        # Spend with CORP! auto-included by wallet
        for u in utxos:
            if not (u["txid"] == a2utxo["txid"] and u["vout"] == a2utxo["vout"]):
                node.lockunspent(False, [{"txid": u["txid"], "vout": u["vout"]}])
        txid3 = node.sendtoaddress(node.getnewaddress(), 2.5)
        node.generate(1)


if __name__ == '__main__':
    P2AHTest().main()


