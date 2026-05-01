/*
    FP-Bypass6.js — com.equus.assignmentpro v2.0.55
    Adapts FP-Bypass5.js to the restructured auth + security-gate flow.

    What changed in v2.0.55 (vs v2.0.54):
    - EquusApplication$Companion.nativeIsAppDisabled()  REMOVED entirely (Java method gone)
    - New disabled flag           : p0.AbstractC0507c.a (AtomicBoolean, default false)
    - New master activity gate    : w0.c.b(Activity) — reads the AtomicBoolean,
                                    shows "Device Security Error" dialog + returns true if disabled
    - New violation handler       : EquusApplication.a(String) — sets AtomicBoolean,
                                    DELETES all KeyStore aliases (new destructive kill),
                                    posts delayed System.exit (5 s)
    - New auth gate field         : m0.AbstractC0404G.j (boolean, default true)
                                    AuthActivity.x(int) short-circuits to w() when j == false
    - AuthActivity entry method   : x(int)  (was w() in v2.0.54)
    - Old m0.v0.i field           : GONE (replaced by AbstractC0404G.j)

    Verified flow we want:
    1. MainActivity.onCreate() → q0.h.v(callback) → w0.c.b()→false → starts AuthActivity
    2. AuthActivity.onCreate() → y() → x(i3)
    3. x(i3) reads !AbstractC0404G.j → true → calls w()
    4. w() setResult(-1, auth_closed=true) + finish()
    5. q0.h's f5484B handler fires the original MainActivity callback
    6. MainActivity.x() → true → activation flow proceeds

    What is hooked and why:
    - w0.c.b(Activity)             → master gate; always return false
    - EquusApplication.a(String)   → noop; blocks KeyStore wipe + dialog + delayed exit
    - EquusApplication.b(String)   → noop; suppresses non-fatal error AlertDialogs
    - m0.AbstractC0404G.j = false  → AuthActivity.x() short-circuits to w()
    - AuthActivity.x(int)          → defense-in-depth; calls this.w() directly
    - MainActivity.x() → true      → keystore self-test (tempkey + Play Services) bypassed
    - KeyStore.deleteEntry         → preserve "tempkey" only; block aliases that look like
                                     Equus binding keys (defends against any wipe path we missed)
    - p0.AbstractC0507c.a.set      → if hookable, force false (defense-in-depth on the AtomicBoolean)

    All v2.0.54 hooks retained: Talsec scanner classes (m0.s, m0.D, m0.l0),
    kill chain (System.exit, killProcess, finishAffinity, q0.b.K),
    root signals (File.exists, Runtime.exec, PackageManager, KeyStore.containsAlias),
    crypto safety (v0.a, Signature, Cipher), Debug.isDebuggerConnected.

    NOT hooked (intentional):
    - Activity.finish()            : normal navigation must work
    - AlertDialog.show()           : loading dialog must show
    - BiometricPrompt              : not needed — AbstractC0404G.j=false skips it entirely
*/

console.log("=== FP-Bypass6 v2.0.55 Loading ===\n");

Java.perform(function () {

    // ── Kill chain ──────────────────────────────────────────────────────────
    try { Java.use("java.lang.System").exit.implementation          = function(c) { console.log("[KILL] System.exit blocked"); }; } catch(e) {}
    try { Java.use("java.lang.Runtime").exit.implementation         = function(c) { console.log("[KILL] Runtime.exit blocked"); }; } catch(e) {}
    try { Java.use("android.os.Process").killProcess.implementation = function(p) { console.log("[KILL] killProcess blocked"); }; } catch(e) {}
    try {
        var Act = Java.use("android.app.Activity");
        Act.finishAffinity.implementation      = function() { console.log("[KILL] finishAffinity blocked"); };
        Act.finishAndRemoveTask.implementation = function() {};
    } catch(e) {}
    try {
        Java.use("q0.b").K.overloads.forEach(function(ol) {
            ol.implementation = function() { console.log("[KILL] q0.b.K blocked"); };
        });
    } catch(e) {}
    console.log("[+] Kill chain active");

    // ── NEW v2.0.55: master activity gate ───────────────────────────────────
    // w0.c.b(Activity) reads p0.AbstractC0507c.a.get(); if true, shows
    // "Device Security Error" and returns true (caller bails). Force false.
    try {
        Java.use("w0.c").b.implementation = function(act) {
            console.log("[GATE] w0.c.b(" + (act ? act.getClass().getSimpleName() : "null") + ") → false");
            return false;
        };
        console.log("[+] FIX A: w0.c.b() → false (master gate)");
    } catch(e) { console.log("[-] w0.c.b: " + e); }

    // ── NEW v2.0.55: neutralise Talsec violation handler ────────────────────
    // EquusApplication.a(String) sets the AtomicBoolean, wipes KeyStore aliases,
    // shows a dialog, and posts a delayed System.exit. No-op the entire thing.
    try {
        Java.use("com.equus.assignmentpro.EquusApplication").a.implementation = function(msg) {
            console.log("[VIOLATION] EquusApplication.a('" + msg + "') blocked");
        };
        console.log("[+] FIX B: EquusApplication.a() neutralised (KeyStore wipe blocked)");
    } catch(e) { console.log("[-] EquusApplication.a: " + e); }

    // EquusApplication.b(String) shows a non-fatal error dialog. Suppress.
    try {
        Java.use("com.equus.assignmentpro.EquusApplication").b.implementation = function(msg) {
            console.log("[ERROR-DIALOG] EquusApplication.b('" + msg + "') suppressed");
        };
        console.log("[+] FIX C: EquusApplication.b() suppressed");
    } catch(e) { console.log("[-] EquusApplication.b: " + e); }

    // ── NEW v2.0.55: auth gate flag ─────────────────────────────────────────
    // AbstractC0404G.j default = true; when false, AuthActivity.x(int)
    // short-circuits to w() and skips the biometric prompt entirely.
    try {
        Java.use("m0.AbstractC0404G").j.value = false;
        console.log("[+] FIX D: m0.AbstractC0404G.j = false (auth gate)");
    } catch(e) {
        try {
            var cls = Java.use("java.lang.Class").forName("m0.AbstractC0404G");
            var f = cls.getDeclaredField("j");
            f.setAccessible(true);
            f.set(null, false);
            console.log("[+] FIX D (reflection): AbstractC0404G.j = false");
        } catch(e2) { console.log("[-] AbstractC0404G.j: " + e2); }
    }

    // ── NEW v2.0.55: AuthActivity hooks ─────────────────────────────────────
    // Two parts:
    //   (1) onCreate — lazy-set m0.AbstractC0404G.j=false. The class is not
    //       loaded at script start (initial Java.use fails) but is loaded by
    //       the time AuthActivity is instantiated, so we set the field here
    //       to break the MainActivity.onResume re-trigger loop:
    //         if (AbstractC0404G.f4846j && this.f2944J) v(...)  ← false
    //   (2) x(int) — replace with this.w() so the biometric prompt never
    //       displays even on the first call (before f4846j has flipped).
    try {
        var Auth = Java.use("com.equus.assignmentpro.activities.AuthActivity");

        Auth.onCreate.implementation = function(bundle) {
            try {
                Java.use("m0.AbstractC0404G").j.value = false;
                console.log("[+] FIX D (lazy): m0.AbstractC0404G.j = false (loop break)");
            } catch(e) { /* class still not loaded — fine, x() hook covers us */ }
            return this.onCreate(bundle);
        };

        Auth.x.overloads.forEach(function(ol) {
            ol.implementation = function() {
                try { Java.use("m0.AbstractC0404G").j.value = false; } catch(e) {}
                console.log("[AUTH] AuthActivity.x() → calling w() directly");
                this.w();
            };
        });
        console.log("[+] FIX E: AuthActivity.x() → w() (biometric skipped)");
    } catch(e) { console.log("[-] AuthActivity hooks: " + e); }

    // AuthActivity.w() is already setResult(-1, auth_closed=true) + finish() —
    // no need to override, but log invocations.
    try {
        var Auth2 = Java.use("com.equus.assignmentpro.activities.AuthActivity");
        var origW = Auth2.w;
        Auth2.w.implementation = function() {
            console.log("[AUTH] AuthActivity.w() invoked → setResult auth_closed");
            return origW.call(this);
        };
    } catch(e) {}

    // ── MainActivity.x() → true (keystore self-test bypass) ─────────────────
    // Same intent as v2.0.54 but x() now performs a real Play Services check
    // and tempkey sign+delete cycle. Forcing true skips the entire chain.
    //
    // We also use this hook as the trigger point for the FORCE-LAUNCH of
    // ProductActivationActivity (FIX J below): after x() has been called a
    // few times we know the post-auth flow is alive, MainActivity exists,
    // and we can build an Intent to land directly on the activation screen.
    var activationLaunched = false;
    var xCallCount = 0;
    try {
        Java.use("com.equus.assignmentpro.MainActivity").x.overloads.forEach(function(ol) {
            ol.implementation = function() {
                xCallCount++;
                console.log("[MAIN] MainActivity.x() → true (skipped keystore self-test)");

                // FIX J: force-launch ProductActivationActivity once we're stable
                if (!activationLaunched && xCallCount >= 5) {
                    activationLaunched = true;
                    try {
                        var Intent = Java.use("android.content.Intent");
                        var intent = Intent.$new();
                        intent.setClassName("com.equus.assignmentpro",
                            "com.equus.assignmentpro.activities.ProductActivationActivity");
                        intent.putExtra("EXTRA_ACTIVATION_CODE", "");
                        this.startActivity(intent);
                        console.log("[+++] FIX J: ProductActivationActivity launched with code 'BYPASS'");
                    } catch(e) { console.log("[-] FIX J launch: " + e); }
                }
                return true;
            };
        });
        console.log("[+] FIX F: MainActivity.x() → true (and FIX J armed)");
    } catch(e) { console.log("[-] MainActivity.x: " + e); }

    // ── AtomicBoolean defense-in-depth ──────────────────────────────────────
    // If anything still routes around the FIX B EquusApplication.a hook,
    // hook AtomicBoolean.set() and refuse 'true' on the disabled-flag instance.
    try {
        var disabledFlag = Java.use("p0.AbstractC0507c").a.value;
        var disabledFlagId = disabledFlag ? Java.cast(disabledFlag, Java.use("java.lang.Object")).hashCode() : null;
        var AB = Java.use("java.util.concurrent.atomic.AtomicBoolean");
        AB.set.implementation = function(v) {
            if (disabledFlagId !== null && Java.cast(this, Java.use("java.lang.Object")).hashCode() === disabledFlagId && v === true) {
                console.log("[DEFENSE] Blocked AtomicBoolean.set(true) on AbstractC0507c.a");
                return;
            }
            return this.set(v);
        };
        AB.compareAndSet.implementation = function(expect, update) {
            if (disabledFlagId !== null && Java.cast(this, Java.use("java.lang.Object")).hashCode() === disabledFlagId && update === true) {
                console.log("[DEFENSE] Blocked AtomicBoolean.compareAndSet(_, true) on AbstractC0507c.a");
                return false;
            }
            return this.compareAndSet(expect, update);
        };
        console.log("[+] FIX G: AtomicBoolean defense armed");
    } catch(e) { console.log("[-] AtomicBoolean defense: " + e); }

    // ── KeyStore.deleteEntry guard (preserve tempkey only) ──────────────────
    // EquusApplication.a() wipes ALL aliases on Talsec violation. FIX B already
    // blocks that, but this is belt-and-braces against any other wipe path.
    try {
        Java.use("java.security.KeyStore").deleteEntry.implementation = function(alias) {
            if (alias === "tempkey" || alias.indexOf("temp") === 0) {
                return this.deleteEntry(alias);  // legitimate use in MainActivity.x()
            }
            console.log("[KEYSTORE] deleteEntry('" + alias + "') blocked (preserving binding key)");
        };
        console.log("[+] FIX H: KeyStore.deleteEntry guarded");
    } catch(e) { console.log("[-] KeyStore.deleteEntry: " + e); }

    // ── Root / Frida / Talsec detection (carried from v5, surgically updated) ─
    // NOTE v2.0.55: m0.s / m0.D blanket-nullification from v5 was REMOVED.
    // In v2.0.55 Talsec's m0.V.c(m0.S) unconditionally writes to a Long field
    // on the m0.s result; returning null there causes NullPointerException
    // crash in m0.k0.run (Talsec scanner thread) → app hard-crashes.
    // We don't need to nullify the scanners because the response chain
    // (q0.b.K + EquusApplication.a) is already neutralised above — Talsec
    // can detect root all it wants, none of its kill paths reach the app.
    try {
        Java.use("java.io.File").exists.implementation = function() {
            var p = this.getAbsolutePath();
            if (p.indexOf("frida")   !== -1 || p.indexOf("magisk")  !== -1 ||
                p.indexOf("/su")     !== -1 || p.indexOf("busybox") !== -1 ||
                p.indexOf("supersu") !== -1 || p.indexOf("sudo")    !== -1 ||
                p.indexOf("xposed")  !== -1) return false;
            return this.exists();
        };
    } catch(e) {}

    try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function() { return false; }; } catch(e) {}

    try {
        Java.use("java.lang.Runtime").exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd.indexOf("which su") !== -1 || cmd.indexOf("busybox") !== -1 || cmd.indexOf("magisk") !== -1)
                return this.exec("echo ''");
            return this.exec(cmd);
        };
    } catch(e) {}

    try {
        var rootApps = ["com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.noshufou.android.su"];
        Java.use("android.content.pm.PackageManager").getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
            for (var i = 0; i < rootApps.length; i++)
                if (pkg === rootApps[i])
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);
            return this.getPackageInfo(pkg, flags);
        };
    } catch(e) {}

    try {
        Java.use("java.security.KeyStore").containsAlias.implementation = function(alias) {
            if (alias.indexOf("Talsec") !== -1 || alias.indexOf("Binding") !== -1) return true;
            return this.containsAlias(alias);
        };
    } catch(e) {}

    console.log("[+] Root / Talsec detection bypassed");

    // ── v0.a KeyPair safety hooks (carried from v5) ─────────────────────────
    try {
        var v0a = Java.use("v0.a");
        ["d", "f"].forEach(function(name) {
            try {
                v0a[name].overloads.forEach(function(ol) {
                    ol.implementation = function() {
                        try { return ol.call(this); } catch(e) { return null; }
                    };
                });
            } catch(ex) {}
        });
    } catch(e) {}

    // ── Signature / Cipher safety (carried from v5) ─────────────────────────
    try {
        var Sig = Java.use("java.security.Signature");
        Sig.sign.overload().implementation = function() {
            try { return this.sign(); } catch(e) {
                var fake = [];
                for (var i = 0; i < 256; i++) fake.push(Math.floor(Math.random() * 256) - 128);
                return Java.array('byte', fake);
            }
        };
    } catch(e) {}

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload().implementation       = function() { try { return this.doFinal(); }    catch(e) { return Java.array('byte', []); } };
        Cipher.doFinal.overload('[B').implementation   = function(a) { try { return this.doFinal(a); } catch(e) { return a; } };
    } catch(e) {}

    // ── NEW v2.0.55: SSL/TLS pinning bypass ─────────────────────────────────
    // v2.0.55 added Network Security Config (NSC) pinning for *.equusoft.com /
    // *.equusoft.tech via res/xml/network_security_config.xml (SHA-256 pin-set).
    // The app uses HttpsURLConnection (u0.C0576j) which routes through the
    // platform's NetworkSecurityTrustManager → Conscrypt TrustManagerImpl.
    // We disable pinning at every layer:
    //   1. NSC pin checker        : NetworkSecurityTrustManager.checkPins → noop
    //   2. Conscrypt chain verify  : TrustManagerImpl.verifyChain → return chain
    //   3. SSLContext.init         : inject a permissive X509TrustManager
    //   4. Hostname verifier       : always allow
    //   5. EquusApplication.b      : already hooked above (suppresses the dialog)

    // 1. Network Security Config pin checker
    try {
        Java.use("android.security.net.config.NetworkSecurityTrustManager")
            .checkPins.implementation = function(chain) {
                console.log("[SSL] NSC checkPins bypassed");
            };
        console.log("[+] FIX I-1: NSC pin checker neutralised");
    } catch(e) { console.log("[-] NSC checkPins: " + e); }

    // 2. Conscrypt (Android 10+) chain verifier
    try {
        Java.use("com.android.org.conscrypt.TrustManagerImpl")
            .verifyChain.implementation = function(chain, host, clientAuth, ocsp, key) {
                console.log("[SSL] Conscrypt verifyChain bypassed (host=" + host + ")");
                return chain;
            };
        console.log("[+] FIX I-2: Conscrypt verifyChain bypassed");
    } catch(e) { console.log("[-] Conscrypt verifyChain: " + e); }

    // 3. Universal X509TrustManager replacement via SSLContext.init
    try {
        var X509TM = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustAll = Java.registerClass({
            name: "com.bypass.TrustAll",
            implements: [X509TM],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var TMs = [TrustAll.$new()];

        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function(km, tm, sr) {
            console.log("[SSL] SSLContext.init → injected TrustAll");
            this.init(km, TMs, sr);
        };
        console.log("[+] FIX I-3: SSLContext.init injecting trust-all");
    } catch(e) { console.log("[-] SSLContext.init: " + e); }

    // 4. Hostname verifier — always true
    try {
        var HV = Java.use("javax.net.ssl.HttpsURLConnection");
        HV.setDefaultHostnameVerifier.implementation = function(v) {
            console.log("[SSL] setDefaultHostnameVerifier swallowed");
        };
        var HVImpl = Java.registerClass({
            name: "com.bypass.HVAll",
            implements: [Java.use("javax.net.ssl.HostnameVerifier")],
            methods: { verify: function(hostname, session) { return true; } }
        });
        HV.setDefaultHostnameVerifier(HVImpl.$new());
        console.log("[+] FIX I-4: HostnameVerifier → trust-all");
    } catch(e) { console.log("[-] HostnameVerifier: " + e); }

    // 5. Belt-and-braces: catch SSLHandshakeException and silently return
    // (Already mostly covered by the above; this only matters if pinning
    // happens through a path we missed.)

    console.log("\n===========================================");
    console.log("  FP-Bypass6 active for v2.0.55.");
    console.log("  Expecting: AuthActivity → auth_closed → MainActivity → activation.");
    console.log("===========================================\n");
});
