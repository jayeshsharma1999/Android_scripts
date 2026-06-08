console.log("[+] Final fingerprint bypass loaded!");

Java.perform(function () {

    function createResult() {
        var CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
        var AuthResult   = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        return AuthResult.$new(CryptoObject.$new(null));
    }

    // Hook framework authenticate (no CryptoObject) - directly force success
    try {
        var Prompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        var auth1 = Prompt['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
        
        auth1.implementation = function (cancel, executor, callback) {
            console.log("[+] authenticate() intercepted -> BYPASS");
            callback.onAuthenticationSucceeded(createResult());
        };
        console.log("[+] Hooked: authenticate() #1");
    } catch (e) { console.log("[-] #1: " + e); }

    // Hook framework authenticate (with CryptoObject) - directly force success
    try {
        var Prompt2 = Java.use('android.hardware.biometrics.BiometricPrompt');
        var auth2 = Prompt2['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
        
        auth2.implementation = function (crypto, cancel, executor, callback) {
            console.log("[+] authenticate2() intercepted -> BYPASS");
            callback.onAuthenticationSucceeded(createResult());
        };
        console.log("[+] Hooked: authenticate() #2");
    } catch (e) { console.log("[-] #2: " + e); }

    // Hook FingerprintManager.authenticate - directly force success
    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        var fpAuth = FingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
        
        fpAuth.implementation = function (crypto, cancel, flags, callback, handler) {
            console.log("[+] FingerprintManager.authenticate() intercepted -> BYPASS");
            var AuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
            var result = AuthResult.$new(crypto, null, 0);
            callback.onAuthenticationSucceeded(result);
        };
        console.log("[+] Hooked: FingerprintManager.authenticate()");
    } catch (e) { console.log("[-] FP: " + e); }

    console.log("[+] Ready.");
});
