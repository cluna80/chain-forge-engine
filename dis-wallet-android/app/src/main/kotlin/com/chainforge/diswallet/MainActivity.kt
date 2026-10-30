package com.chainforge.diswallet

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.chainforge.diswallet.databinding.ActivityMainBinding
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: WalletViewModel
    private var pendingChallenge: ConsentReview.Challenge? = null
    private var pendingServer: WalletViewModel.ServerChallenge? = null

    private val requestCameraPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) startQrScan()
        else binding.tvStatus.text = "Camera permission denied"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        viewModel = ViewModelProvider(this)[WalletViewModel::class.java]

        lifecycleScope.launch {
            val restored = viewModel.restoreKeys()
            if (restored.isNotEmpty()) binding.tvStatus.text = restored
        }
        binding.etVendorId.setText("docs")
        binding.etVendorOrigin.setText("https://docs.example.com")

        binding.btnProvision.setOnClickListener {
            val vendorId = binding.etVendorId.text.toString().trim()
            val vendorOrigin = binding.etVendorOrigin.text.toString().trim()
            lifecycleScope.launch {
                binding.progressBar.visibility = View.VISIBLE
                binding.tvStatus.text = ""
                val result = viewModel.provision(vendorId, vendorOrigin)
                binding.progressBar.visibility = View.GONE
                binding.tvResult.text = result
            }
        }

        binding.btnScan.setOnClickListener {
            when {
                ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                    == PackageManager.PERMISSION_GRANTED -> startQrScan()
                else -> requestCameraPermission.launch(Manifest.permission.CAMERA)
            }
        }

        binding.btnReview.setOnClickListener {
            pendingServer = null
            present(binding.etChallenge.text.toString())
        }

        binding.btnApprove.setOnClickListener { approvePending() }

        binding.btnRefuse.setOnClickListener {
            pendingChallenge = null
            pendingServer = null
            binding.cardReview.visibility = View.GONE
            binding.tvStatus.text = "Refused. Nothing was signed."
        }

        binding.btnTest.setOnClickListener {
            lifecycleScope.launch {
                binding.progressBar.visibility = View.VISIBLE
                binding.tvResult.text = "Running self-test..."
                binding.tvStatus.text = ""
                val result = viewModel.selfTest()
                binding.progressBar.visibility = View.GONE
                binding.tvResult.text = result
                binding.tvStatus.text = if (result.startsWith("SUCCESS")) "✅ DIS Working!" else "❌ Failed"
            }
        }

        binding.btnServerAuth.setOnClickListener {
            val serverUrl = binding.etServerUrl.text.toString().trim()
            val vendorId = binding.etVendorId.text.toString().trim()
            val resourceId = binding.etResourceId.text.toString().trim()
            lifecycleScope.launch {
                binding.progressBar.visibility = View.VISIBLE
                binding.tvStatus.text = "Fetching a challenge..."
                try {
                    val prepared = viewModel.fetchServerChallenge(serverUrl, vendorId, resourceId, "read")
                    pendingServer = prepared
                    val raw = prepared.challenge.toString()
                    binding.etChallenge.setText(raw)
                    present(raw)
                    binding.tvStatus.text = "Read the card. Nothing is signed until you approve."
                } catch (e: Exception) {
                    pendingServer = null
                    binding.tvResult.text = "ERROR: ${e.message}"
                    binding.tvStatus.text = "❌ Failed"
                } finally {
                    binding.progressBar.visibility = View.GONE
                }
            }
        }

        binding.btnCopy.setOnClickListener {
            val text = binding.tvResult.text.toString()
            if (text.isNotEmpty()) {
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                clipboard.setPrimaryClip(android.content.ClipData.newPlainText("DIS Proof", text))
                binding.tvStatus.text = "Copied!"
            }
        }
    }

    private fun startQrScan() {
        val integrator = IntentIntegrator(this)
        integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        integrator.setPrompt("Scan vendor challenge QR code")
        integrator.setCameraId(0)
        integrator.setBeepEnabled(true)
        integrator.setBarcodeImageEnabled(false)
        integrator.setOrientationLocked(false)
        integrator.initiateScan()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null && result.contents != null) {
            val scannedJson = result.contents
            binding.etChallenge.setText(scannedJson)
            binding.tvStatus.text = "QR scanned. Review it before you sign."
            pendingServer = null
            present(scannedJson)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun present(raw: String) {
        val vendorId = binding.etVendorId.text.toString().trim()
        when (val review = ConsentReview.parse(raw, vendorId, viewModel.vendorOrigin(vendorId), System.currentTimeMillis())) {
            is ConsentReview.Challenge -> {
                pendingChallenge = review
                val scopes = if (review.scopes.isEmpty()) "—" else review.scopes.joinToString(", ")
                val expiry = if (review.expiresAtSec <= 0) {
                    "No expiry"
                } else {
                    val left = review.expiresAtSec - System.currentTimeMillis() / 1000
                    if (left <= 0) "Expired" else "${left / 60}m ${left % 60}s left"
                }
                binding.tvReviewTitle.text = "CHALLENGE"
                binding.tvReviewBody.text = buildString {
                    append(review.action)
                    append(" · ")
                    append(review.resource)
                    append("\nAudience  ")
                    append(review.origin)
                    append("\nScopes  ")
                    append(scopes)
                    append("\nExpires  ")
                    append(expiry)
                    append("\nKey  ")
                    append(review.vendorId.ifBlank { "—" })
                    append("\n\nA signature here does not send QCB.")
                }
                showWarning(review.blockReason)
                binding.btnApprove.visibility = if (review.blockReason == null) View.VISIBLE else View.GONE
                binding.cardReview.visibility = View.VISIBLE
            }
            is ConsentReview.Transfer -> {
                pendingChallenge = null
                binding.tvReviewTitle.text = "SIGNED TX ENVELOPE"
                binding.tvReviewBody.text = buildString {
                    append("chain_id  ")
                    append(review.chainId)
                    append("\nsender  ")
                    append(review.sender)
                    append("\nnonce  ")
                    append(review.nonce)
                    append("\ngas_limit  ")
                    append(review.gasLimit)
                    append("\nto  ")
                    append(review.to)
                    append("\namount  ")
                    append(review.amount)
                    append(" ")
                    append(review.denom)
                    append("\n\n")
                    append(review.preimage)
                    append("\n\nThe vendor key cannot sign this. Chain signing is not in this build.")
                }
                showWarning(null)
                binding.btnApprove.visibility = View.GONE
                binding.cardReview.visibility = View.VISIBLE
            }
            is ConsentReview.Invalid -> {
                pendingChallenge = null
                binding.tvReviewTitle.text = "NOT SIGNED"
                binding.tvReviewBody.text = review.reason
                showWarning(null)
                binding.btnApprove.visibility = View.GONE
                binding.cardReview.visibility = View.VISIBLE
            }
        }
    }

    private fun showWarning(reason: String?) {
        if (reason.isNullOrBlank()) {
            binding.tvReviewWarn.visibility = View.GONE
            binding.tvReviewWarn.text = ""
        } else {
            binding.tvReviewWarn.visibility = View.VISIBLE
            binding.tvReviewWarn.text = reason
        }
    }

    private fun approvePending() {
        val challenge = pendingChallenge ?: return
        if (challenge.blockReason != null) return
        val server = pendingServer
        lifecycleScope.launch {
            binding.progressBar.visibility = View.VISIBLE
            binding.tvStatus.text = "Signing..."
            val proof = viewModel.sign(challenge.vendorId, challenge.raw)
            val result = if (server != null && proof.startsWith("✅")) {
                val rawProof = proof.removePrefix("✅ DIS Proof:\n")
                viewModel.submitServerProof(server.serverUrl, server.vendorId, server.challenge, rawProof)
            } else {
                proof
            }
            binding.progressBar.visibility = View.GONE
            binding.tvResult.text = result
            binding.tvStatus.text = if (result.startsWith("✅")) "✅ Signed" else "❌ Error"
            binding.cardReview.visibility = View.GONE
            pendingChallenge = null
            pendingServer = null
        }
    }
}
