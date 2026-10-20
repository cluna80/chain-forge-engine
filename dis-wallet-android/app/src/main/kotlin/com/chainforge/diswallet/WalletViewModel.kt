package com.chainforge.diswallet

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class WalletViewModel(application: Application) : AndroidViewModel(application) {

    private val wallet = DisWallet()
    private val keyStore = WalletKeyStore(application)
    private var restored = false

    suspend fun restoreKeys(): String = withContext(Dispatchers.Default) {
        if (restored) return@withContext ""
        restored = true
        val ids = keyStore.getVendorIds()
        if (ids.isEmpty()) return@withContext ""
        var count = 0
        for (id in ids) {
            val key = keyStore.loadVendor(id) ?: continue
            val result = wallet.importKey(id, key.origin, key.policy, key.pk, key.sk)
            if (!result.startsWith("ERROR")) count++
        }
        if (count > 0) "✅ Restored $count vendor key(s)" else ""
    }

    suspend fun provision(vendorId: String, vendorOrigin: String): String =
        withContext(Dispatchers.Default) {
            try {
                val pk = wallet.provision(vendorId, vendorOrigin, "v1")
                if (pk.startsWith("ERROR")) return@withContext pk
                // Export and persist the key
                val exported = wallet.exportKey(vendorId)
                if (!exported.startsWith("ERROR")) {
                    val parts = exported.split(":")
                    if (parts.size == 2) {
                        keyStore.saveVendor(vendorId, vendorOrigin, "v1", parts[0], parts[1])
                    }
                }
                "✅ Provisioned & saved!\nPublic key:\n${pk.take(48)}..."
            } catch (e: Exception) {
                "Provision failed: ${e.message}"
            }
        }

    suspend fun sign(vendorId: String, challengeJson: String): String =
        withContext(Dispatchers.Default) {
            try {
                val proof = wallet.signChallenge(vendorId, challengeJson)
                if (proof.startsWith("ERROR")) proof
                else "✅ DIS Proof:\n$proof"
            } catch (e: Exception) {
                "Sign failed: ${e.message}"
            }
        }

    suspend fun selfTest(): String =
        withContext(Dispatchers.Default) {
            try {
                val pk = wallet.provision("test-vendor", "https://test.example.com", "v1")
                if (pk.startsWith("ERROR")) return@withContext "FAILED at provision: $pk"
                val now = System.currentTimeMillis() / 1000
                val challenge = """{"challenge_id":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"nonce":[16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1],"issued_at":$now,"expires_at":${now+299},"resource_id":"document:001","action":"read","scopes":["document:read"],"policy_id":"v1"}"""
                val proof = wallet.signChallenge("test-vendor", challenge)
                if (proof.startsWith("ERROR")) return@withContext "FAILED at sign: $proof"
                "SUCCESS!\n\nPublic key:\n${pk.take(48)}...\n\nProof:\n$proof"
            } catch (e: Exception) {
                "FAILED: ${e.message}"
            }
        }

    fun getSavedVendors(): Set<String> = keyStore.getVendorIds()
}
