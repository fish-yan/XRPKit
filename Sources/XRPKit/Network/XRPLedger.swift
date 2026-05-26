//
//  Ledger.swift
//  XRPKit
//
//  Created by Mitch Lang on 5/10/19.
//

import Foundation

enum LedgerError: Error {
    case runtimeError(String)
}

public struct XRPLedger {

    // JSON-RPC
    private static var url: URL = .xrpl_rpc_Testnet
    
    private init() {
        
    }
    
    public static func setURL(endpoint: URL) {
        self.url = endpoint
    }
    
    public static func getTxs(account: String) async throws -> [XRPHistoricalTransaction] {
        let parameters: [String: Any] = [
            "method" : "account_tx",
            "params": [
                [
                    "account" : account,
                    "ledger_index_min" : -1,
                    "ledger_index_max" : -1,
                ]
            ]
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        let info = JSON["result"] as! NSDictionary
        let status = info["status"] as! String
        guard status != "error" else {
            throw LedgerError.runtimeError(info["error_message"] as! String)
        }

        let _array = info["transactions"] as! [NSDictionary]
        let filtered = _array.filter({ (dict) -> Bool in
            let validated = dict["validated"] as! Bool
            let tx = dict["tx"] as! NSDictionary
            let meta = dict["meta"] as! NSDictionary
            let res = meta["TransactionResult"] as! String
            let type = tx["TransactionType"] as! String
            return validated && type == "Payment" && res == "tesSUCCESS"
        })

        let transactions = filtered.map({ (dict) -> XRPHistoricalTransaction in
            let tx = dict["tx"] as! NSDictionary
            let destination = tx["Destination"] as! String
            let source = tx["Account"] as! String
            let amount = tx["Amount"] as! String
            let timestamp = tx["date"] as! Int
            let date = Date(timeIntervalSince1970: 946684800+Double(timestamp))
            let type = account == source ? "Sent" : "Received"
            let address = account == source ? destination : source
            return XRPHistoricalTransaction(type: type, address: address, amount: try! XRPAmount(drops: Int(amount)!), date: date, raw: tx)
        })
        return transactions.sorted(by: { (lh, rh) -> Bool in
            lh.date > rh.date
        })
    }
    
    public static func getBalance(address: String) async throws -> XRPAmount {
        let parameters: [String: Any] = [
            "method" : "account_info",
            "params": [
                [
                    "account" : address
                ]
            ]
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        let info = JSON["result"] as! NSDictionary
        let status = info["status"] as! String
        guard status != "error" else {
            throw LedgerError.runtimeError(info["error_message"] as! String)
        }
        let account = info["account_data"] as! NSDictionary
        let balance = account["Balance"] as! String
        return try! XRPAmount(drops: Int(balance)!)
    }
    
    public static func getAccountInfo(account: String) async throws -> XRPAccountInfo {
        let parameters: [String: Any] = [
            "method" : "account_info",
            "params": [
                [
                    "account" : account,
                    "strict": true,
                    "ledger_index": "current",
                    "queue": true
                ]
            ]
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        let info = JSON["result"] as! NSDictionary
        let status = info["status"] as! String
        guard status != "error" else {
            throw LedgerError.runtimeError(info["error_message"] as! String)
        }
        let account = info["account_data"] as! NSDictionary
        let balance = account["Balance"] as! String
        let address = account["Account"] as! String
        let sequence = account["Sequence"] as! Int
        return XRPAccountInfo(address: address, drops: Int(balance)!, sequence: sequence)
    }
    
    public static func getSignerList(address: String) async throws -> NSDictionary {
        let parameters: [String: Any] = [
            "method" : "account_objects",
            "params": [
                [
                    "account" : address,
                    "ledger_index": "validated",
                    "type": "signer_list",
                ]
            ]
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        let info = JSON["result"] as! NSDictionary
        let status = info["status"] as! String
        guard status != "error" else {
            throw LedgerError.runtimeError(info["error_message"] as! String)
        }
        return info
    }
    
    public static func getPendingEscrows(address: String) async throws -> NSDictionary {
        let parameters: [String: Any] = [
            "method" : "account_objects",
            "params": [
                [
                    "account" : address,
                    "ledger_index": "validated",
                    "type": "escrow",
                ]
            ]
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        let info = JSON["result"] as! NSDictionary
        let status = info["status"] as! String
        guard status != "error" else {
            throw LedgerError.runtimeError(info["error_message"] as! String)
        }
        return info
    }
    
    public static func currentLedgerInfo() async throws -> XRPCurrentLedgerInfo {
        let parameters: [String: Any] = [
            "method" : "fee"
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        let info = JSON["result"] as! NSDictionary
        let drops = info["drops"] as! NSDictionary
        let min = drops["minimum_fee"] as! String
        let max = drops["median_fee"] as! String
        let ledger = info["ledger_current_index"] as! Int
        return XRPCurrentLedgerInfo(index: ledger, minFee: Int(min)!, maxFee: Int(max)!)
    }
    
    public static func submit(txBlob: String) async throws -> NSDictionary {
        let parameters: [String: Any] = [
            "method" : "submit",
            "params": [
                [
                    "tx_blob": txBlob
                ]
            ]
        ]

        let JSON = try await HTTP.post(url: url, parameters: parameters) as! NSDictionary
        return JSON["result"] as! NSDictionary
    }
    
}
