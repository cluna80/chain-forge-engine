package com.chainforge.diswallet

class DisWallet {

    companion object {
        init {
            System.loadLibrary("dis_wallet")
        }
    }

    external fun provision(vendorId: String, vendorOrigin: String, policyId: String): String
    external fun signChallenge(vendorId: String, challengeJson: String): String
    external fun listVendors(): Array<String>
    external fun exportKey(vendorId: String): String
    external fun importKey(vendorId: String, vendorOrigin: String, policyId: String, pkHex: String, skHex: String): String
}
