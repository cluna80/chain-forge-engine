#!/bin/bash
set -e

export ANDROID_HOME=/workspaces/chain-forge-engine/android-sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/26.1.10909125
export NDK_HOME=$ANDROID_NDK_HOME
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH

echo "=== Building DIS Wallet JNI for Android ARM64 ==="
cd /workspaces/chain-forge-engine
cargo build -p dis-wallet-jni --target aarch64-linux-android --release

echo "=== Copying .so to Android project ==="
mkdir -p dis-wallet-android/app/src/main/jniLibs/arm64-v8a
cp target/aarch64-linux-android/release/libdis_wallet.so \
   dis-wallet-android/app/src/main/jniLibs/arm64-v8a/

echo "=== Building APK ==="
cd dis-wallet-android
chmod +x gradlew 2>/dev/null || true
gradle assembleDebug

echo "=== APK ready ==="
find . -name "*.apk" -type f