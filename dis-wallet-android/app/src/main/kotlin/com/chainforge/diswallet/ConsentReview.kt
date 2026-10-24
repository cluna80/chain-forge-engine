package com.chainforge.diswallet

import org.json.JSONArray
import org.json.JSONObject

sealed class ConsentReview {
    data class Challenge(
        val raw: String,
        val vendorId: String,
        val origin: String,
        val resource: String,
        val action: String,
        val scopes: List<String>,
        val expiresAtSec: Long,
        val blockReason: String?,
    ) : ConsentReview()

    data class Transfer(
        val chainId: String,
        val sender: String,
        val nonce: String,
        val gasLimit: String,
        val to: String,
        val amount: String,
        val denom: String,
        val preimage: String,
    ) : ConsentReview()

    data class Invalid(val reason: String) : ConsentReview()

    companion object {
        const val TX_DOMAIN = "chain-forge/pq-tx/v1"

        fun parse(raw: String, vendorId: String, savedOrigin: String?, nowMs: Long): ConsentReview {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) return Invalid("Paste a challenge or scan a QR code.")
            val json = try {
                JSONObject(trimmed)
            } catch (_: Exception) {
                return Invalid("That is not JSON.")
            }
            val body = json.optJSONObject("body")
            val type = json.optString("type").ifEmpty { body?.optString("type").orEmpty() }
            if (type == "Transfer" || (json.has("chain_id") && body != null)) {
                return transfer(json, body ?: json)
            }
            return challenge(json, trimmed, vendorId, savedOrigin, nowMs)
        }

        private fun challenge(
            json: JSONObject,
            raw: String,
            vendorId: String,
            savedOrigin: String?,
            nowMs: Long,
        ): ConsentReview {
            val resource = json.optString("resource_id").ifEmpty { json.optString("resource") }
            val action = json.optString("action")
            val origin = json.optString("rp_origin").ifEmpty { json.optString("origin") }
            val scopes = json.optJSONArray("scopes").strings()
            val expiresAtSec = when {
                json.has("expires_at") -> json.optLong("expires_at")
                json.has("exp") -> {
                    val exp = json.optLong("exp")
                    if (exp > 10_000_000_000L) exp / 1000 else exp
                }
                else -> 0L
            }
            val native = json.has("challenge_id") &&
                json.has("nonce") &&
                json.has("expires_at") &&
                json.has("resource_id")
            val reasons = mutableListOf<String>()
            if (!native) {
                reasons += "This is not a vendor challenge the phone can sign."
            }
            if (resource.isBlank()) reasons += "No resource."
            if (action.isBlank()) reasons += "No action."
            if (scopes.isEmpty()) reasons += "No scopes."
            if (expiresAtSec > 0 && nowMs / 1000 >= expiresAtSec) reasons += "This challenge is expired."
            if (!savedOrigin.isNullOrBlank() && origin.isNotBlank() && origin != savedOrigin) {
                reasons += "Audience is $origin. This key was provisioned for $savedOrigin."
            }
            if (action.isNotBlank() && scopes.isNotEmpty() &&
                scopes.none { it == action || it.endsWith(":$action") }
            ) {
                reasons += "Action $action is outside the scopes on this challenge."
            }
            return Challenge(
                raw = raw,
                vendorId = vendorId.ifBlank { json.optString("rp_id").ifEmpty { json.optString("rpId") } },
                origin = origin.ifBlank { "Not on this challenge" },
                resource = resource.ifBlank { "—" },
                action = action.ifBlank { "—" },
                scopes = scopes,
                expiresAtSec = expiresAtSec,
                blockReason = reasons.joinToString("\n").ifBlank { null },
            )
        }

        private fun transfer(envelope: JSONObject, body: JSONObject): ConsentReview {
            val chainId = envelope.optString("chain_id").ifEmpty { "qcb-testnet-4node" }
            val denom = body.optString("denom").ifEmpty { "uqcb" }
            val amountValue = body.opt("amount")
            val bodyJson = JSONObject()
                .put("type", "Transfer")
                .put("to", body.optString("to"))
                .put("amount", amountValue ?: 0)
                .put("denom", denom)
            return Transfer(
                chainId = chainId,
                sender = envelope.optString("sender").ifBlank { "—" },
                nonce = if (envelope.has("nonce")) envelope.opt("nonce").toString() else "—",
                gasLimit = if (envelope.has("gas_limit")) envelope.opt("gas_limit").toString() else "80000",
                to = body.optString("to").ifBlank { "—" },
                amount = amountValue?.toString() ?: "—",
                denom = denom,
                preimage = "$TX_DOMAIN\n$chainId\n$bodyJson",
            )
        }

        private fun JSONArray?.strings(): List<String> {
            if (this == null) return emptyList()
            return (0 until length()).mapNotNull { index ->
                optString(index).takeIf { it.isNotEmpty() }
            }
        }
    }
}
