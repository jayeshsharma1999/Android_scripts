/*
    COMBINED Bypass — com.equus.assignmentpro
    Merges bio_root_bypass.js (verified working) + safe additions from FP_22.js

    Verified flow:
    1. MainActivity.v(C0491c) → nativeIsAppDisabled()→false → launches AuthActivity
    2. AuthActivity.w() → v0.i=false → setResult(-1, auth_closed=true) + finish()
    3. f5331B callback → C0491c.b() → x()→true → Firebase token → e.j() server call
    4. S0.e case 12 → ProductActivationActivity (activation code screen)

    What is hooked and why:
    - nativeIsAppDisabled()→false   : checked in v(), AuthActivity, ProductActivationActivity, S0.e case 12, e.j()
    - AuthActivity.w() direct hook  : replaces entire method — bypasses biometric hw check AND field check
    - v0.i = false                  : secondary safety net (field 'i' in m0.v0)
    - MainActivity.x()→true         : allows C0491c.b() to proceed with Firebase init + server call
    - System.exit / finishAffinity  : handles S0.e case 10 kill chain without blocking case 12
    - q0.b.K                        : Talsec response handler — blocked to prevent kill signals
    - File.exists                   : hides root/frida/magisk paths
    - m0.s, m0.D, m0.l0            : Talsec root scanner classes — neutralised
    - Runtime.exec                  : blocks shell-based root checks (which su, magisk)
    - PackageManager.getPackageInfo : hides root app packages
    - KeyStore.containsAlias        : spoofs Talsec binding key presence
    - Debug.isDebuggerConnected     : hides debugger
    - v0.a KeyPair methods          : neutralise keypair-based security checks
    - Signature / Cipher            : prevent crypto failures from crashing hooks

    NOT hooked (intentional):
    - AlertDialog.show()            : loading dialog MUST show or NPE crash in w0.b
    - Activity.finish()             : normal navigation must work
    - S0.e.run()                    : case 12 must run to launch ProductActivationActivity
    - BiometricPrompt               : not needed — v0.i=false skips biometric entirely
    - String.equals                 : would log every string comparison — massive false positives
*/

console.log("=== Combined Bypass Loading ===\n");

Java.perform(function () {

    // ── Kill chain (handles S0.e case 10 without blocking case 12) ──────────
    try { Java.use("java.lang.System").exit.implementation          = function(c) { console.log("[KILL] System.exit blocked"); }; } catch(e) {}
    try { Java.use("java.lang.Runtime").exit.implementation         = function(c) { console.log("[KILL] Runtime.exit blocked"); }; } catch(e) {}
    try { Java.use("android.os.Process").killProcess.implementation = function(p) { console.log("[KILL] killProcess blocked"); }; } catch(e) {}
    try {
        var Act = Java.use("android.app.Activity");
        Act.finishAffinity.implementation      = function() { console.log("[KILL] finishAffinity blocked"); };
        Act.finishAndRemoveTask.implementation = function() {};
        // NOTE: Activity.finish() is NOT blocked — normal screen navigation must work
    } catch(e) {}
    try {
        Java.use("q0.b").K.overloads.forEach(function(ol) {
            ol.implementation = function() { console.log("[KILL] q0.b.K blocked"); };
        });
    } catch(e) {}
    console.log("[+] Kill chain active");

    // ── Root / Frida / Talsec detection bypass ───────────────────────────────
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

    // Talsec root scanner — nullify all methods
    try {
        Java.use("m0.s").class.getDeclaredMethods().forEach(function(m) {
            try {
                Java.use("m0.s")[m.getName()].overloads.forEach(function(ol) {
                    ol.implementation = function() { return null; };
                });
            } catch(ex) {}
        });
    } catch(e) {}

    // Talsec orchestrator — return safe values per return type
    try {
        Java.use("m0.D").class.getDeclaredMethods().forEach(function(m) {
            try {
                Java.use("m0.D")[m.getName()].overloads.forEach(function(ol) {
                    var r = ol.returnType ? ol.returnType.className : "void";
                    ol.implementation = function() {
                        if (r === "boolean") return true;
                        if (r === "void") return;
                        return null;
                    };
                });
            } catch(ex) {}
        });
    } catch(e) {}

    try { Java.use("m0.l0").run.implementation = function() {}; } catch(e) {}
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

    // ── v0.a KeyPair hooks (from FP_22) ─────────────────────────────────────
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
        console.log("[+] v0.a KeyPair methods hooked");
    } catch(e) {}

    // ── Signature safety hook (from FP_22) ──────────────────────────────────
    try {
        var Sig = Java.use("java.security.Signature");
        Sig.sign.overload().implementation = function() {
            try { return this.sign(); } catch(e) {
                var fake = [];
                for (var i = 0; i < 256; i++) fake.push(Math.floor(Math.random() * 256) - 128);
                return Java.array('byte', fake);
            }
        };
        console.log("[+] Signature hooked");
    } catch(e) {}

    // ── Cipher safety hook (from FP_22) ─────────────────────────────────────
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload().implementation       = function() { try { return this.doFinal(); }    catch(e) { return Java.array('byte', []); } };
        Cipher.doFinal.overload('[B').implementation   = function(a) { try { return this.doFinal(a); } catch(e) { return a; } };
        console.log("[+] Cipher hooked");
    } catch(e) {}

    // ── FIX 1: nativeIsAppDisabled() → false ────────────────────────────────
    try {
        Java.use("com.equus.assignmentpro.EquusApplication$Companion")
            .nativeIsAppDisabled.implementation = function() {
                console.log("[ROOT] nativeIsAppDisabled() → false");
                return false;
            };
        console.log("[+] FIX 1: nativeIsAppDisabled() → false");
    } catch(e) { console.log("[-] nativeIsAppDisabled: " + e); }

    // ── FIX 2a: AuthActivity.w() directly hooked ────────────────────────────
    // AuthActivity.w() first checks biometric hardware availability via fVar.d(i3).
    // If d() returns non-0, the method exits BEFORE reaching the v0.f4897i check,
    // so the field hook alone is not reliable. Hooking w() directly guarantees bypass.
    // This replicates the exact "skip biometric" path from the source:
    //   setResult(-1, {auth_closed:true}) + finish()
    try {
        var AuthActivity = Java.use("com.equus.assignmentpro.activities.AuthActivity");
        AuthActivity.w.implementation = function() {
            console.log("[AUTH] w() → skipping biometric, returning auth result");
            var Intent = Java.use("android.content.Intent");
            var intent = Intent.$new();
            intent.putExtra("auth_closed", true);
            this.setResult(-1, intent);
            this.finish();
        };
        console.log("[+] FIX 2a: AuthActivity.w() directly bypassed");
    } catch(e) { console.log("[-] AuthActivity.w hook: " + e); }

    // ── FIX 2b: v0.i = false → secondary safety net ─────────────────────────
    // Actual smali field name is 'i'; JADX renames it to 'f4897i'
    try {
        Java.use("m0.v0").i.value = false;
        console.log("[+] FIX 2b: v0.i = false (secondary safety net)");
    } catch(e) {
        try {
            var v0Cls = Java.use("java.lang.Class").forName("m0.v0");
            var iField = v0Cls.getDeclaredField("i");
            iField.setAccessible(true);
            iField.set(null, false);
            console.log("[+] FIX 2b (reflection): v0.i = false");
        } catch(e2) { console.log("[-] v0.i: " + e2); }
    }

    // ── FIX 3: MainActivity.x() → true ──────────────────────────────────────
    try {
        Java.use("com.equus.assignmentpro.MainActivity").x.overloads.forEach(function(ol) {
            ol.implementation = function() {
                console.log("[MAIN] x() → true");
                return true;
            };
        });
        console.log("[+] FIX 3: MainActivity.x() → true");
    } catch(e) { console.log("[-] x() hook: " + e); }

    console.log("\n===========================================");
    console.log("  All bypasses active.");
    console.log("  App will auto-proceed to activation screen.");
    console.log("===========================================\n");
});
