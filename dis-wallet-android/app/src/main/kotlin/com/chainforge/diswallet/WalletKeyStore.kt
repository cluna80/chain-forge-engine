package com.chainforge.diswallet

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class WalletKeyStore(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "dis_wallet_keys",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveVendor(id: String, origin: String, policy: String, pk: String, sk: String) {
        prefs.edit()
            .putString("vendor_origin_$id", origin)
            .putString("vendor_policy_$id", policy)
            .putString("vendor_pk_$id", pk)
            .putString("vendor_sk_$id", sk)
            .putStringSet("vendor_ids", getVendorIds() + id)
            .apply()
    }

    fun loadVendor(id: String): VendorKey? {
        val origin = prefs.getString("vendor_origin_$id", null) ?: return null
        val policy = prefs.getString("vendor_policy_$id", null) ?: return null
        val pk = prefs.getString("vendor_pk_$id", null) ?: return null
        val sk = prefs.getString("vendor_sk_$id", null) ?: return null
        return VendorKey(id, origin, policy, pk, sk)
    }

    fun getVendorIds(): Set<String> =
        prefs.getStringSet("vendor_ids", emptySet()) ?: emptySet()

    fun deleteVendor(id: String) {
        prefs.edit()
            .remove("vendor_origin_$id")
            .remove("vendor_policy_$id")
            .remove("vendor_pk_$id")
            .remove("vendor_sk_$id")
            .putStringSet("vendor_ids", getVendorIds() - id)
            .apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }
}

data class VendorKey(
    val id: String,
    val origin: String,
    val policy: String,
    val pk: String,
    val sk: String
)
