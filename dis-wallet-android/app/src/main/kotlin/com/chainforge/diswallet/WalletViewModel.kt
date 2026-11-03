package com.chainforge.diswallet

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

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

    /** Rotate the ML-DSA keypair for vendorId. Persists the new key and returns
     *  "old_pk_hex:new_pk_hex" for the caller to re-enroll with the vendor server. */
    suspend fun rotateKey(vendorId: String): String = withContext(Dispatchers.Default) {
        try {
            val result = wallet.rotateKey(vendorId)
            if (result.startsWith("ERROR")) return@withContext result
            val parts = result.split(":")
            if (parts.size != 2) return@withContext "ERROR: unexpected rotate result"
            val (oldPk, newPk) = parts
            // Persist new key — fetch full export to get new sk.
            val exported = wallet.exportKey(vendorId)
            if (!exported.startsWith("ERROR")) {
                val ep = exported.split(":")
                if (ep.size == 2) {
                    val vendor = keyStore.loadVendor(vendorId)
                    if (vendor != null) keyStore.saveVendor(vendorId, vendor.origin, vendor.policy, ep[0], ep[1])
                }
            }
            "✅ Key rotated\nOld: ${oldPk.take(32)}...\nNew: ${newPk.take(32)}..."
        } catch (e: Exception) {
            "Rotate failed: ${e.message}"
        }
    }

    fun getSavedVendors(): Set<String> = keyStore.getVendorIds()

    fun vendorOrigin(vendorId: String): String? = keyStore.loadVendor(vendorId)?.origin

    data class ServerChallenge(
        val serverUrl: String,
        val vendorId: String,
        val challenge: JSONObject,
    )

    /** Enroll and fetch a challenge. Does not sign. */
    suspend fun fetchServerChallenge(
        serverUrl: String,
        vendorId: String,
        resourceId: String,
        action: String,
    ): ServerChallenge = withContext(Dispatchers.IO) {
        val client = VendorServerClient(serverUrl)
        val exported = wallet.exportKey(vendorId)
        if (exported.startsWith("ERROR")) error("Vendor not provisioned. Provision first.")
        val pk = exported.split(":").firstOrNull() ?: error("Could not get the public key.")
        client.enroll(vendorId, pk)
        val challengeResp = client.challenge(vendorId, resourceId, action)
        if (challengeResp.optString("status") != "ok") {
            error(challengeResp.optString("message").ifBlank { "The server did not return a challenge." })
        }
        ServerChallenge(serverUrl, vendorId, challengeResp.getJSONObject("challenge"))
    }

    suspend fun submitServerProof(
        serverUrl: String,
        vendorId: String,
        challenge: JSONObject,
        proofStr: String,
    ): String = withContext(Dispatchers.IO) {
        try {
            val proofObj = JSONObject(proofStr)
            val verifyResp = VendorServerClient(serverUrl).verify(
                vendorId,
                challenge,
                proofObj.getString("public_key"),
                proofObj.getString("signature"),
            )
            if (verifyResp.optString("status") == "verified") {
                "✅ SERVER VERIFIED!\n\nAccess granted to:\n${verifyResp.optString("resource_id")}\nAction: ${verifyResp.optString("action")}\nWallet: ${verifyResp.optString("wallet_id")}"
            } else {
                "❌ Rejected: ${verifyResp.optString("message")}"
            }
        } catch (e: Exception) {
            "ERROR: ${e.message}"
        }
    }
}
