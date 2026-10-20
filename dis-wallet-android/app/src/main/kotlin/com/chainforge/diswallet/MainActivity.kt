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

        binding.btnSign.setOnClickListener {
            val challenge = binding.etChallenge.text.toString().trim()
            val vendorId = binding.etVendorId.text.toString().trim()
            if (challenge.isEmpty()) {
                binding.tvResult.text = "Please scan a QR code or paste a challenge"
                return@setOnClickListener
            }
            signChallenge(vendorId, challenge)
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
                binding.tvStatus.text = "Authenticating with server..."
                val result = viewModel.serverAuth(serverUrl, vendorId, resourceId, "read")
                binding.progressBar.visibility = View.GONE
                binding.tvResult.text = result
                binding.tvStatus.text = if (result.startsWith("✅")) "✅ Verified!" else "❌ Failed"
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
            binding.tvStatus.text = "✅ QR scanned! Tap Sign to proceed."
            // Auto-sign after scan
            val vendorId = binding.etVendorId.text.toString().trim()
            signChallenge(vendorId, scannedJson)
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun signChallenge(vendorId: String, challenge: String) {
        lifecycleScope.launch {
            binding.progressBar.visibility = View.VISIBLE
            binding.tvStatus.text = "Signing..."
            val result = viewModel.sign(vendorId, challenge)
            binding.progressBar.visibility = View.GONE
            binding.tvResult.text = result
            binding.tvStatus.text = if (result.startsWith("✅")) "✅ Signed!" else "❌ Error"
        }
    }
}
