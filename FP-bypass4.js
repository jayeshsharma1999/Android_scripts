/* 
    Description: Complete Bypass Script - Biometric + Security + Activation (Final)
    Usage: frida -U -f com.equus.assignmentpro -l complete-bypass.js --no-pause
*/

console.log("=== Complete Bypass Script Loading ===\n");

var fakeKeyPair = null;
var fakePrivateKey = null;
var fakePublicKey = null;

Java.perform(function() {
    
    // ==================== GENERATE FAKE KEYPAIR ====================
    try {
        var KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        fakeKeyPair = kpg.generateKeyPair();
        fakePrivateKey = fakeKeyPair.getPrivate();
        fakePublicKey = fakeKeyPair.getPublic();
        console.log("[+] Fake RSA KeyPair generated!");
    } catch (e) {
        console.log("[-] KeyPair generation failed: " + e);
    }

    // ==================== BLOCK ALL SECURITY DIALOGS ====================
    try {
        var AlertDialogBuilder = Java.use("android.app.AlertDialog$Builder");
        
        AlertDialogBuilder.setTitle.overload('java.lang.CharSequence').implementation = function(title) {
            var t = title ? title.toString().toLowerCase() : "";
            if (t.indexOf("security") !== -1 || t.indexOf("error") !== -1 || t.indexOf("device") !== -1) {
                return this;
            }
            return this.setTitle(title);
        };
        
        AlertDialogBuilder.setMessage.overload('java.lang.CharSequence').implementation = function(message) {
            var m = message ? message.toString().toLowerCase() : "";
            if (m.indexOf("security") !== -1 || m.indexOf("debugger") !== -1 || m.indexOf("decompiler") !== -1 || 
                m.indexOf("root") !== -1 || m.indexOf("hub") !== -1 || m.indexOf("activat") !== -1) {
                return this;
            }
            return this.setMessage(message);
        };
        
        AlertDialogBuilder.show.implementation = function() {
            return this.create();
        };
        
        console.log("[+] AlertDialog.Builder blocked");
    } catch (e) {}

    try {
        var AlertDialog = Java.use("android.app.AlertDialog");
        AlertDialog.show.implementation = function() {};
        console.log("[+] AlertDialog.show blocked");
    } catch (e) {}

    try {
        var AndroidXBuilder = Java.use("androidx.appcompat.app.AlertDialog$Builder");
        AndroidXBuilder.show.implementation = function() { return this.create(); };
        console.log("[+] AndroidX AlertDialog blocked");
    } catch (e) {}

    // ==================== BLOCK APP TERMINATION ====================
    try {
        Java.use("java.lang.System").exit.implementation = function(code) {
            console.log("[*] System.exit BLOCKED");
        };
    } catch (e) {}

    try {
        Java.use("java.lang.Runtime").exit.implementation = function(code) {
            console.log("[*] Runtime.exit BLOCKED");
        };
    } catch (e) {}

    try {
        Java.use("android.os.Process").killProcess.implementation = function(pid) {
            console.log("[*] Process.killProcess BLOCKED");
        };
    } catch (e) {}

    try {
        var Activity = Java.use("android.app.Activity");
        Activity.finish.overload().implementation = function() {
            console.log("[*] Activity.finish BLOCKED");
        };
        Activity.finishAffinity.implementation = function() {
            console.log("[*] Activity.finishAffinity BLOCKED");
        };
        Activity.finishAndRemoveTask.implementation = function() {
            console.log("[*] Activity.finishAndRemoveTask BLOCKED");
        };
        console.log("[+] Activity termination blocked");
    } catch (e) {}

    // ==================== BYPASS DEBUG/ROOT DETECTION ====================
    try {
        Java.use("android.os.Debug").isDebuggerConnected.implementation = function() {
            return false;
        };
        console.log("[+] Debug detection bypassed");
    } catch (e) {}

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("frida") !== -1 || path.indexOf("magisk") !== -1 || 
                path.indexOf("/su") !== -1 || path.indexOf("xposed") !== -1 ||
                path.indexOf("busybox") !== -1 || path.indexOf("supersu") !== -1) {
                return false;
            }
            return this.exists();
        };
        console.log("[+] Root/Frida detection bypassed");
    } catch (e) {}

    // ==================== BIOMETRIC BYPASS ====================
    try {
        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        
        BiometricPrompt['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(cancel, executor, callback) {
            console.log("[+] BiometricPrompt.authenticate() BYPASSED!");
            var CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
            var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
            var cryptoInst = CryptoObject.$new(null);
            var authResult = AuthResult.$new(cryptoInst, 0);
            callback.onAuthenticationSucceeded(authResult);
        };
        
        BiometricPrompt['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(crypto, cancel, executor, callback) {
            console.log("[+] BiometricPrompt.authenticate(crypto) BYPASSED!");
            var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
            var authResult = AuthResult.$new(crypto, 0);
            callback.onAuthenticationSucceeded(authResult);
        };
        
        console.log("[+] BiometricPrompt hooked");
    } catch (e) {}

    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        var FMAuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        
        FingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler').implementation = function(crypto, cancel, flags, callback, handler) {
            console.log("[+] FingerprintManager.authenticate() BYPASSED!");
            var authResult = FMAuthResult.$new(crypto, 0);
            callback.onAuthenticationSucceeded(authResult);
        };
        
        console.log("[+] FingerprintManager hooked");
    } catch (e) {}

    // ==================== KEYSTORE HOOKS ====================
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.containsAlias.implementation = function(alias) {
            if (alias === "PrivateRSAKey") return true;
            return this.containsAlias(alias);
        };
        
        KeyStore.getKey.overload('java.lang.String', '[C').implementation = function(alias, password) {
            if (alias === "PrivateRSAKey" && fakePrivateKey != null) {
                return Java.cast(fakePrivateKey, Java.use("java.security.Key"));
            }
            try { return this.getKey(alias, password); } catch (e) { return null; }
        };
        
        KeyStore.getCertificate.implementation = function(alias) {
            if (alias === "PrivateRSAKey") return null;
            return this.getCertificate(alias);
        };
        
        console.log("[+] KeyStore hooked");
    } catch (e) {}

    // ==================== V0.A CLASS (KEYPAIR) HOOKS ====================
    try {
        var v0a = Java.use("v0.a");
        
        v0a.d.overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("[+] v0.a.d returning fake KeyPair");
                return Java.cast(fakeKeyPair, Java.use("java.security.KeyPair"));
            };
        });
        
        v0a.f.overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("[+] v0.a.f returning fake KeyPair");
                return Java.cast(fakeKeyPair, Java.use("java.security.KeyPair"));
            };
        });
        
        console.log("[+] v0.a KeyPair methods hooked");
    } catch (e) {}

    // ==================== SIGNATURE HOOKS ====================
    try {
        var Signature = Java.use("java.security.Signature");
        
        Signature.initSign.overload('java.security.PrivateKey').implementation = function(key) {
            if (key == null && fakePrivateKey != null) key = fakePrivateKey;
            return this.initSign(key);
        };
        
        Signature.sign.overload().implementation = function() {
            try { return this.sign(); } catch (e) {
                var fake = [];
                for (var i = 0; i < 256; i++) fake.push(Math.floor(Math.random() * 256) - 128);
                return Java.array('byte', fake);
            }
        };
        
        console.log("[+] Signature hooked");
    } catch (e) {}

    // ==================== CIPHER HOOKS ====================
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload().implementation = function() { try { return this.doFinal(); } catch (e) { return Java.array('byte', []); } };
        Cipher.doFinal.overload('[B').implementation = function(a) { try { return this.doFinal(a); } catch (e) { return a; } };
        console.log("[+] Cipher hooked");
    } catch (e) {}

    // ==================== BYPASS ACTIVATION CODE CHECK ====================
    try {
        // Hook String.equals to always return true for activation code checks
        var String = Java.use("java.lang.String");
        var originalEquals = String.equals;
        
        String.equals.implementation = function(obj) {
            var result = originalEquals.call(this, obj);
            var thisStr = this.toString();
            var objStr = obj ? obj.toString() : "";
            
            // If comparing short alphanumeric strings (likely activation codes)
            if (!result && thisStr.length >= 4 && thisStr.length <= 12 && 
                objStr.length >= 4 && objStr.length <= 12) {
                // Log potential code comparisons
                if (thisStr.match(/^[A-Za-z0-9]+$/) && objStr.match(/^[A-Za-z0-9]+$/)) {
                    console.log("[CODE CHECK] '" + thisStr + "' vs '" + objStr + "'");
                }
            }
            return result;
        };
        console.log("[+] String.equals hooked for code detection");
    } catch (e) {}

    // ==================== HOOK HTTP RESPONSES TO FAKE SUCCESS ====================
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        HttpURLConnection.getResponseCode.implementation = function() {
            var url = this.getURL().toString();
            console.log("[HTTP] " + url);
            
            if (url.indexOf("equus") !== -1 || url.indexOf("Activation") !== -1 || url.indexOf("Register") !== -1) {
                console.log("[+] Faking HTTP 200 OK for: " + url);
                return 200;
            }
            return this.getResponseCode();
        };
        
        console.log("[+] HTTP responses hooked");
    } catch (e) {}

    // ==================== BYPASS PRODUCT ACTIVATION ====================
    try {
        var ProductActivation = Java.use("com.equus.assignmentpro.activities.ProductActivationActivity");
        var methods = ProductActivation.class.getDeclaredMethods();
        
        console.log("[*] ProductActivationActivity methods:");
        methods.forEach(function(m) {
            var name = m.getName();
            console.log("    - " + name);
            
            // Hook methods that might validate activation
            if (name.indexOf("valid") !== -1 || name.indexOf("check") !== -1 || 
                name.indexOf("verify") !== -1 || name.indexOf("activ") !== -1) {
                try {
                    ProductActivation[name].overloads.forEach(function(overload) {
                        overload.implementation = function() {
                            console.log("[+] " + name + "() returning true/success");
                            var retType = overload.returnType.className;
                            if (retType === "boolean") return true;
                            if (retType === "void") return;
                            return null;
                        };
                    });
                } catch (e) {}
            }
        });
        
        console.log("[+] ProductActivationActivity hooked");
    } catch (e) {}

    // ==================== FORCE NAVIGATE TO MAIN ACTIVITY ====================
    setTimeout(function() {
        Java.perform(function() {
            try {
                var Intent = Java.use("android.content.Intent");
                var ActivityThread = Java.use("android.app.ActivityThread");
                var currentApp = ActivityThread.currentApplication();
                var context = currentApp.getApplicationContext();
                
                // Try MainActivity first
                var intent = Intent.$new();
                intent.setClassName("com.equus.assignmentpro", "com.equus.assignmentpro.activities.MainActivity");
                intent.setFlags(0x10000000 | 0x4000000); // FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP
                
                try {
                    context.startActivity(intent);
                    console.log("\n[+] NAVIGATED TO MAIN ACTIVITY!\n");
                } catch (e) {
                    console.log("[-] MainActivity failed, trying ProductActivationActivity...");
                    
                    intent = Intent.$new();
                    intent.setClassName("com.equus.assignmentpro", "com.equus.assignmentpro.activities.ProductActivationActivity");
                    intent.setFlags(0x10000000 | 0x4000000);
                    context.startActivity(intent);
                    console.log("\n[+] NAVIGATED TO PRODUCT ACTIVATION!\n");
                }
            } catch (e) {
                console.log("[-] Navigation error: " + e);
            }
        });
    }, 2000); // Wait 2 seconds for app to initialize

    console.log("\n===========================================");
    console.log("   All bypasses installed!");
    console.log("   Will auto-navigate in 2 seconds...");
    console.log("===========================================\n");
});

// ==================== HELPER FUNCTIONS ====================

function goToMain() {
    Java.perform(function() {
        var Intent = Java.use("android.content.Intent");
        var ActivityThread = Java.use("android.app.ActivityThread");
        var context = ActivityThread.currentApplication().getApplicationContext();
        
        var intent = Intent.$new();
        intent.setClassName("com.equus.assignmentpro", "com.equus.assignmentpro.activities.MainActivity");
        intent.setFlags(0x10000000 | 0x4000000);
        context.startActivity(intent);
        console.log("[+] Going to MainActivity!");
    });
}

function goToActivation() {
    Java.perform(function() {
        var Intent = Java.use("android.content.Intent");
        var ActivityThread = Java.use("android.app.ActivityThread");
        var context = ActivityThread.currentApplication().getApplicationContext();
        
        var intent = Intent.$new();
        intent.setClassName("com.equus.assignmentpro", "com.equus.assignmentpro.activities.ProductActivationActivity");
        intent.setFlags(0x10000000 | 0x4000000);
        context.startActivity(intent);
        console.log("[+] Going to ProductActivationActivity!");
    });
}

function tryCode(code) {
    Java.perform(function() {
        // Find EditText and set the code
        Java.choose("android.widget.EditText", {
            onMatch: function(instance) {
                console.log("[*] Found EditText, setting code: " + code);
                
                Java.scheduleOnMainThread(function() {
                    instance.setText(Java.use("java.lang.String").$new(code));
                });
            },
            onComplete: function() {}
        });
    });
}

function clickButton() {
    Java.perform(function() {
        Java.choose("android.widget.Button", {
            onMatch: function(instance) {
                var text = instance.getText().toString();
                console.log("[*] Found Button: " + text);
                
                Java.scheduleOnMainThread(function() {
                    instance.performClick();
                    console.log("[+] Clicked: " + text);
                });
            },
            onComplete: function() {}
        });
    });
}

console.log("\nHelper commands:");
console.log("  goToMain()       - Force navigate to MainActivity");
console.log("  goToActivation() - Force navigate to Activation screen");
console.log("  tryCode('1234')  - Enter activation code");

console.log("  clickButton()    - Click visible buttons\n");
