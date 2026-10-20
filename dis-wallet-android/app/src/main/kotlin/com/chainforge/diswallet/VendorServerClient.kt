package com.chainforge.diswallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class VendorServerClient(private val serverUrl: String) {

    private fun post(endpoint: String, body: JSONObject): JSONObject {
        val url = URL("$serverUrl$endpoint")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 10000
        conn.readTimeout = 10000
        OutputStreamWriter(conn.outputStream).use { it.write(body.toString()) }
        val response = conn.inputStream.bufferedReader().readText()
        return JSONObject(response)
    }

    private fun get(endpoint: String): JSONObject {
        val url = URL("$serverUrl$endpoint")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 10000
        conn.readTimeout = 10000
        val response = conn.inputStream.bufferedReader().readText()
        return JSONObject(response)
    }

    suspend fun health(): JSONObject = withContext(Dispatchers.IO) { get("/health") }

    suspend fun enroll(walletId: String, publicKeyHex: String): JSONObject =
        withContext(Dispatchers.IO) {
            post("/enroll", JSONObject().apply {
                put("wallet_id", walletId)
                put("public_key_hex", publicKeyHex)
            })
        }

    suspend fun challenge(walletId: String, resourceId: String, action: String): JSONObject =
        withContext(Dispatchers.IO) {
            post("/challenge", JSONObject().apply {
                put("wallet_id", walletId)
                put("resource_id", resourceId)
                put("action", action)
            })
        }

    suspend fun verify(
        walletId: String,
        challenge: JSONObject,
        publicKeyHex: String,
        signatureHex: String
    ): JSONObject = withContext(Dispatchers.IO) {
        post("/verify", JSONObject().apply {
            put("wallet_id", walletId)
            put("challenge", challenge)
            put("public_key_hex", publicKeyHex)
            put("signature_hex", signatureHex)
        })
    }
}
