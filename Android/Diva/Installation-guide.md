
# Running OWASP DIVA from Source on Modern Android Studio (2026 Guide)

This guide explains how to successfully build and run OWASP DIVA (Damn Insecure and Vulnerable App) from source code on a modern Android Studio environment.

---

# 1. Requirements

Install:

- Android Studio (latest)
- Android SDK
- Java 17+
- Android Emulator

Recommended emulator:

Device: Pixel 3  
Android Version: Android 9 (API 28)

---

# 2. Download DIVA Source

https://github.com/payatu/diva-android

Open in Android Studio.

---

# 3. Fix Gradle / Java Compatibility

Use:

Gradle: 8.5+  
Android Gradle Plugin: 8.2.x  
Java: 17

---

# 4. Fix Android 12 Manifest Requirement

Add exported flag in AndroidManifest.xml:

android:exported="true"

for activities with intent filters.

---

# 5. Migrate Support Library → AndroidX

Replace:

android.support.v7.app.AppCompatActivity

with

androidx.appcompat.app.AppCompatActivity

Replace design widgets:

android.support.design.widget.*

with

com.google.android.material.*

---

# 6. Fix Layout XML

Replace:

android.support.design.widget.CoordinatorLayout

with

androidx.coordinatorlayout.widget.CoordinatorLayout

Replace:

android.support.design.widget.AppBarLayout

with

com.google.android.material.appbar.AppBarLayout

---

# 7. Add Dependency

In app/build.gradle:

implementation 'androidx.coordinatorlayout:coordinatorlayout:1.2.0'
implementation 'androidx.appcompat:appcompat:1.6.1'
implementation 'com.google.android.material:material:1.11.0'

---

# 8. Remove Old Test Files

Delete:

app/src/androidTest/

---

# 9. Build

Build → Rebuild Project

---

# 10. APK Location

app/build/outputs/apk/debug/app-debug.apk

---

# 11. Create Emulator

Device Manager → Pixel 3 → API 28

---

# 12. Install APK

adb install -r app/build/outputs/apk/debug/app-debug.apk

---

# 13. Launch DIVA

Open Diva in emulator.

You should see vulnerabilities:

- Insecure Logging
- Hardcoding Issues
- Insecure Storage
- Input Validation
- Access Control

---

# Useful Debug Command

adb logcat AndroidRuntime:E ActivityManager:E *:S

