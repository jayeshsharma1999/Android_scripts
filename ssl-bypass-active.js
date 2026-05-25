/*
 * Universal SSL Pinning Bypass for Android
 * Covers: TrustManager, OkHttp3 CertificatePinner, Conscrypt, WebView,
 *         HostnameVerifier, SSLContext, network_security_config
 */

Java.perform(function () {
    console.log('[+] SSL Pinning bypass loaded');

    // 1. TrustManagerImpl.verifyChain (Android default)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassing TrustManagerImpl.verifyChain for ' + host);
            return untrustedChain;
        };
        TrustManagerImpl.checkTrustedRecursive.implementation = function () {
            console.log('[+] Bypassing TrustManagerImpl.checkTrustedRecursive');
            return Java.use('java.util.ArrayList').$new();
        };
    } catch (e) {}

    // 2. X509TrustManager (generic)
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'dev.bypass.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );
        SSLContext_init.implementation = function (km, tm, sr) {
            console.log('[+] Overriding SSLContext.init');
            SSLContext_init.call(this, km, TrustManagers, sr);
        };
    } catch (e) {}

    // 3. OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCertificates) {
            console.log('[+] Bypassing OkHttp3 CertificatePinner.check for ' + host);
            return;
        };
        CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (host, cleanedPeerCertificatesFn) {
            console.log('[+] Bypassing OkHttp3 CertificatePinner.check$okhttp for ' + host);
            return;
        };
    } catch (e) {}

    // 4. OkHttp3 HostnameVerifier
    try {
        var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
            return true;
        };
        OkHostnameVerifier.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () {
            return true;
        };
    } catch (e) {}

    // 5. Generic HostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var Verifier = Java.registerClass({
            name: 'dev.bypass.HostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (v) {
            console.log('[+] Overriding setDefaultHostnameVerifier');
            return HttpsURLConnection.setDefaultHostnameVerifier.call(this, Verifier.$new());
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
            return HttpsURLConnection.setHostnameVerifier.call(this, Verifier.$new());
        };
    } catch (e) {}

    // 6. WebViewClient onReceivedSslError
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[+] WebView SSL error bypassed');
            handler.proceed();
        };
    } catch (e) {}

    // 7. TrustKit (commonly used pinning library)
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
            return true;
        };
    } catch (e) {}

    // 8. AppCelerator Titanium
    try {
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function () {};
    } catch (e) {}

    // 9. Network Security Config
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.getPins.implementation = function () {
            console.log('[+] Bypassing NetworkSecurityConfig.getPins');
            return Java.use('java.util.HashSet').$new();
        };
    } catch (e) {}

    // 10. Conscrypt platform default
    try {
        var ConscryptTM = Java.use('com.google.android.gms.org.conscrypt.TrustManagerImpl');
        ConscryptTM.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Bypassing GMS Conscrypt TrustManagerImpl for ' + host);
            return untrustedChain;
        };
    } catch (e) {}

    console.log('[+] All hooks installed');
});
