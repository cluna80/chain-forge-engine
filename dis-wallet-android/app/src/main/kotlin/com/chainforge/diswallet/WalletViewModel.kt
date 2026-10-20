package com.chainforge.diswallet

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class WalletViewModel : ViewModel() {

    private val wallet = DisWallet()

    suspend fun provision(vendorId: String, vendorOrigin: String): String =
        withContext(Dispatchers.Default) {
            try {
                val pubKey = wallet.provision(vendorId, vendorOrigin, "v1")
                if (pubKey.startsWith("ERROR")) pubKey
                else "✅ Provisioned!\nPublic key:\n${pubKey.take(48)}..."
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
                // Step 1: provision
                val pk = wallet.provision("test-vendor", "https://test.example.com", "v1")
                if (pk.startsWith("ERROR")) return@withContext "FAILED at provision: $pk"

                // Step 2: build a valid challenge
                val now = System.currentTimeMillis() / 1000
                val challenge = """{"challenge_id":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"nonce":[16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1],"issued_at":$now,"expires_at":${now+299},"resource_id":"document:001","action":"read","scopes":["document:read"],"policy_id":"v1"}"""

                // Step 3: sign
                val proof = wallet.signChallenge("test-vendor", challenge)
                if (proof.startsWith("ERROR")) return@withContext "FAILED at sign: $proof"

                "SUCCESS!\n\nPublic key (first 48 chars):\n${pk.take(48)}...\n\nProof:\n$proof"
            } catch (e: Exception) {
                "FAILED: ${e.message}"
            }
        }
}
