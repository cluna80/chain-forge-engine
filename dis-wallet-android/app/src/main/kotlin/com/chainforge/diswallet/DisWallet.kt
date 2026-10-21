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
    /** Rotate the keypair for vendorId. Returns "old_pk_hex:new_pk_hex" or "ERROR: ...".
     *  Caller must: (1) call VendorServerClient.rotateKey(oldPk, newPk),
     *               (2) persist the new key to WalletKeyStore before any app restart. */
    external fun rotateKey(vendorId: String): String
}
