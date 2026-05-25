/*
 * Android Biometric/Fingerprint Bypass
 * Forces onAuthenticationSucceeded for:
 *   - androidx.biometric.BiometricPrompt (Jetpack — most common)
 *   - android.hardware.biometrics.BiometricPrompt (Android 9+ native)
 *   - android.hardware.fingerprint.FingerprintManager (legacy)
 *   - Cipher-bound biometric flows
 *   - KeyguardManager (PIN/pattern fallback)
 */

Java.perform(function () {
    console.log('[BIO] Biometric bypass loaded');

    // ---------- 1. androidx.biometric.BiometricPrompt (Jetpack) ----------
    try {
        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
        var AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');

        var lastCallback = null;
        var lastExecutor = null;

        // Capture callback from constructors
        BiometricPrompt.$init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                for (var i = 0; i < args.length; i++) {
                    if (args[i] && args[i].$className && args[i].$className.indexOf('AuthenticationCallback') !== -1) {
                        lastCallback = args[i];
                        console.log('[BIO] Captured AuthenticationCallback from BiometricPrompt ctor');
                    }
                    if (args[i] && args[i].$className && args[i].$className.indexOf('Executor') !== -1) {
                        lastExecutor = args[i];
                    }
                }
                return ov.apply(this, arguments);
            };
        });

        // Override authenticate() to immediately fire success
        BiometricPrompt.authenticate.overloads.forEach(function (ov) {
            ov.implementation = function () {
                console.log('[BIO] androidx BiometricPrompt.authenticate() -> faking success');
                var self = this;
                var args = arguments;
                // Try to find the stored callback (might be 'mClient' field or similar)
                var cb = lastCallback;
                try {
                    // Construct AuthenticationResult — try common ctor signatures
                    var result = null;
                    try {
                        // (CryptoObject, int) — newer
                        result = AuthResult.$new(null, 2);
                    } catch (e1) {
                        try {
                            // (CryptoObject) — older
                            result = AuthResult.$new(null);
                        } catch (e2) {
                            // (CryptoObject, int, boolean) — variation
                            try { result = AuthResult.$new(null, 2, false); } catch (e3) {}
                        }
                    }
                    if (cb && result) {
                        cb.onAuthenticationSucceeded(result);
                        console.log('[BIO] Fired onAuthenticationSucceeded');
                        return;
                    }
                } catch (e) {
                    console.log('[BIO] AuthResult construction failed: ' + e);
                }
                // Fallback: let the original call happen, then our callback hook will swallow failure
                return ov.apply(self, args);
            };
        });

        // Redirect any error/failure callback into a no-op (or success)
        var AuthCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
        AuthCallback.onAuthenticationError.implementation = function (errorCode, errString) {
            console.log('[BIO] Swallowed onAuthenticationError (' + errorCode + ' / ' + errString + ')');
        };
        AuthCallback.onAuthenticationFailed.implementation = function () {
            console.log('[BIO] Swallowed onAuthenticationFailed');
        };
    } catch (e) {
        console.log('[BIO] androidx.biometric not present: ' + e);
    }

    // ---------- 2. android.hardware.biometrics.BiometricPrompt (Android 9+) ----------
    try {
        var NativeBP = Java.use('android.hardware.biometrics.BiometricPrompt');
        var NativeAR = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        var NativeCB = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');

        NativeBP.authenticate.overloads.forEach(function (ov) {
            ov.implementation = function () {
                console.log('[BIO] native BiometricPrompt.authenticate() -> faking success');
                var args = Array.prototype.slice.call(arguments);
                var callback = null;
                args.forEach(function (a) {
                    if (a && a.$className && a.$className.indexOf('AuthenticationCallback') !== -1) {
                        callback = a;
                    }
                });
                try {
                    if (callback) {
                        var fakeResult = NativeAR.$new(null);
                        callback.onAuthenticationSucceeded(fakeResult);
                        console.log('[BIO] Native fired onAuthenticationSucceeded');
                        return;
                    }
                } catch (e) { console.log('[BIO] native result ctor failed: ' + e); }
                return ov.apply(this, arguments);
            };
        });

        NativeCB.onAuthenticationError.implementation = function (errorCode, errString) {
            console.log('[BIO] native onAuthenticationError swallowed');
        };
        NativeCB.onAuthenticationFailed.implementation = function () {
            console.log('[BIO] native onAuthenticationFailed swallowed');
        };
    } catch (e) {
        console.log('[BIO] native BiometricPrompt not present: ' + e);
    }

    // ---------- 3. FingerprintManager (legacy) ----------
    try {
        var FM = Java.use('android.hardware.fingerprint.FingerprintManager');
        var FMResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');

        // Hook ALL overloads of authenticate
        FM.authenticate.overloads.forEach(function (ov) {
            ov.implementation = function () {
                console.log('[BIO] FingerprintManager.authenticate() -> faking success');
                var args = Array.prototype.slice.call(arguments);
                var crypto = args[0];
                var callback = args[3];
                try {
                    var res = FMResult.$new(crypto, null, 0);
                    callback.onAuthenticationSucceeded(res);
                } catch (e) {
                    try {
                        // Some Android variants have 4-arg AuthenticationResult ctor
                        var res = FMResult.$new(crypto, null, 0, true);
                        callback.onAuthenticationSucceeded(res);
                    } catch (e2) {
                        console.log('[BIO] FM result ctor failed: ' + e2);
                    }
                }
            };
        });

        FM.isHardwareDetected.overloads.forEach(function (ov) {
            ov.implementation = function () { return true; };
        });
        FM.hasEnrolledFingerprints.overloads.forEach(function (ov) {
            ov.implementation = function () { return true; };
        });
        console.log('[BIO] FingerprintManager hooks installed (' + FM.authenticate.overloads.length + ' authenticate overloads)');
    } catch (e) {
        console.log('[BIO] FingerprintManager hook failed: ' + e);
    }

    // ---------- 3b. Enumerate biometric/auth classes the app actually loaded ----------
    try {
        var found = [];
        Java.enumerateLoadedClassesSync().forEach(function (cls) {
            var lc = cls.toLowerCase();
            if ((lc.indexOf('biometric') !== -1 || lc.indexOf('fingerprint') !== -1 ||
                 (lc.indexOf('auth') !== -1 && lc.indexOf('innovapptive') !== -1)) &&
                lc.indexOf('$') === -1) {
                found.push(cls);
            }
        });
        if (found.length) {
            console.log('[BIO-SCAN] Loaded auth-related classes:');
            found.forEach(function (c) { console.log('  - ' + c); });
        } else {
            console.log('[BIO-SCAN] No biometric/fingerprint classes loaded yet (will appear when you tap biometric)');
        }
    } catch (e) {
        console.log('[BIO-SCAN] enumeration failed: ' + e);
    }

    // ---------- 4. BiometricManager.canAuthenticate ----------
    try {
        var BiometricManager = Java.use('androidx.biometric.BiometricManager');
        BiometricManager.canAuthenticate.overloads.forEach(function (ov) {
            ov.implementation = function () {
                console.log('[BIO] BiometricManager.canAuthenticate -> returning SUCCESS');
                return 0; // BIOMETRIC_SUCCESS
            };
        });
    } catch (e) {}
    try {
        var NativeBM = Java.use('android.hardware.biometrics.BiometricManager');
        NativeBM.canAuthenticate.overloads.forEach(function (ov) {
            ov.implementation = function () { return 0; };
        });
    } catch (e) {}

    // ---------- 5. KeyguardManager (device-credential fallback) ----------
    try {
        var KG = Java.use('android.app.KeyguardManager');
        KG.isKeyguardSecure.implementation = function () { return true; };
        KG.isDeviceSecure.overloads.forEach(function (ov) {
            ov.implementation = function () { return true; };
        });
    } catch (e) {}

    // ---------- 6. Cipher-bound biometrics ----------
    // Some apps require Cipher.doFinal to succeed (proving the user authenticated
    // a hardware-backed key). We can't really fake the crypto, but we can detect
    // and log when this pattern is used so you know.
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (data) {
            try {
                return this.doFinal(data);
            } catch (e) {
                console.log('[BIO] Cipher.doFinal threw (crypto-bound biometric?): ' + e);
                throw e;
            }
        };
    } catch (e) {}

    console.log('[BIO] All biometric hooks installed');
});
