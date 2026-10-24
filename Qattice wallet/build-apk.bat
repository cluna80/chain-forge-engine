@echo off
:: Build Qattice APK for Android
:: Run this from inside "Qattice wallet\" on your Windows laptop.
:: Requires: Node.js, Android Studio (with SDK + Build Tools installed)

echo === 1. Build static web assets ===
call npm run build:cap
if errorlevel 1 goto fail

echo === 2. Sync to Android project ===
call npx cap sync android
if errorlevel 1 goto fail

echo === 3. Build debug APK ===
cd android
call gradlew.bat assembleDebug
if errorlevel 1 goto fail
cd ..

echo.
echo === Done! APK is at: ===
echo   android\app\build\outputs\apk\debug\app-debug.apk
echo.
echo Transfer it to your phone and install (allow Unknown Sources).
goto end

:fail
echo.
echo BUILD FAILED — check output above.
exit /b 1

:end
