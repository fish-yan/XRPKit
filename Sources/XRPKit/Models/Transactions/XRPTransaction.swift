//
//  XRPTransaction.swift
//  XRPKit
//
//  Created by Mitch Lang on 5/10/19.
//

import Foundation

public class XRPTransaction: XRPRawTransaction {
    
    var wallet: XRPWallet
    
    @available(*, unavailable)
    override init(fields: [String:Any]) {
      fatalError()
    }
    
    internal init(wallet: XRPWallet, fields: [String:Any]) {
        self.wallet = wallet
        var _fields = fields
        _fields["Account"] = wallet.address
        super.init(fields: _fields)
    }
    
    // autofills ledger sequence, fee, and sequence
    func autofill() async throws -> XRPTransaction {
        // network calls to retrive current account and ledger info
        async let ledgerInfo = XRPLedger.currentLedgerInfo()
        async let accountInfo = XRPLedger.getAccountInfo(account: self.wallet.address)
        let (ledger, account) = try await (ledgerInfo, accountInfo)

        // dictionary containing transaction fields
        let filledFields: [String:Any] = [
            "LastLedgerSequence" : ledger.index+5,
            "Fee" : String(ledger.minFee), // FIXME: determine fee automatically
            "Sequence" : account.sequence,
        ]
        self.fields = self.fields.merging(self.enforceJSONTypes(fields: filledFields)) { (_, new) in new }
        return self
    }
    
    public func send() async throws -> NSDictionary {
        // autofill missing transaction fields (online)
        let tx = try await self.autofill()

        // sign the transaction (offline)
        let signedTransaction = try tx.sign(wallet: tx.wallet)

        // submit the transaction (online)
        return try await signedTransaction.submit()
    }
}
