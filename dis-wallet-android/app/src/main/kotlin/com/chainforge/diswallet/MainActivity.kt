package com.chainforge.diswallet

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.chainforge.diswallet.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: WalletViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        viewModel = ViewModelProvider(this)[WalletViewModel::class.java]

        // Auto-fill test values
        binding.etVendorId.setText("docs")
        binding.etVendorOrigin.setText("https://docs.example.com")

        binding.btnProvision.setOnClickListener {
            val vendorId = binding.etVendorId.text.toString().trim()
            val vendorOrigin = binding.etVendorOrigin.text.toString().trim()
            lifecycleScope.launch {
                binding.progressBar.visibility = View.VISIBLE
                val result = viewModel.provision(vendorId, vendorOrigin)
                binding.progressBar.visibility = View.GONE
                binding.tvResult.text = result
                binding.tvStatus.text = ""
            }
        }

        binding.btnSign.setOnClickListener {
            val challenge = binding.etChallenge.text.toString().trim()
            val vendorId = binding.etVendorId.text.toString().trim()
            lifecycleScope.launch {
                binding.progressBar.visibility = View.VISIBLE
                val result = viewModel.sign(vendorId, challenge)
                binding.progressBar.visibility = View.GONE
                binding.tvResult.text = result
                binding.tvStatus.text = ""
            }
        }

        // NEW: built-in self test button
        binding.btnTest.setOnClickListener {
            lifecycleScope.launch {
                binding.progressBar.visibility = View.VISIBLE
                binding.tvResult.text = "Running self-test..."
                val result = viewModel.selfTest()
                binding.progressBar.visibility = View.GONE
                binding.tvResult.text = result
                binding.tvStatus.text = if (result.startsWith("SUCCESS")) "✅ DIS Working!" else "❌ Failed"
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
}
