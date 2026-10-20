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
}