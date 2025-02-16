# FN-DSA (in JavaScript)

FN-DSA is a new *upcoming* post-quantum signature scheme, currently
being defined by NIST as part of their [Post-Quantum Cryptography
Standardization](https://csrc.nist.gov/pqc-standardization) project.
FN-DSA is based on the [Falcon](https://falcon-sign.info/) scheme.

## Important Warnings (Read Them!)

**WARNING (1):** As this file is being written, no FN-DSA draft has been
published yet, and therefore what is implemented here is *not* the
"real" FN-DSA; such a thing does not exist yet. When FN-DSA gets
published (presumably as a draft first, but ultimately as a "final"
standard), this implementation will be adjusted accordingly.
Correspondingly, it is expected that **backward compatiblity will NOT be
maintained**, i.e. that keys and signatures obtained with this code may
cease to be accepted by ulterior versions. Only version 1.0 will provide
such stability, and it will be published only after publication of the
final FN-DSA standard.

**WARNING (2):** If you want to use this code for generating key pairs
or signing data, then you should pause and rethink your life. JavaScript
and the in-browser context are awfully inadequate for serious
cryptographic code; only when an algorithm has been properly integrated
in the [Web Crypto
API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
can it be used with some decent security. I know that whatever I say,
some people will go nuts and make JavaScript implementations of
anything; this code is thus my attempt at mitigating the unavoidable
disaster. JavaScript code is hard to write in a way that does not leak
information through timing measurements, and this implementation makes
only moderate efforts at trying to do so in the signature generation
part. The key pair generation is very much not constant-time at all.

If you just want to *verify* signatures, then that's fine, this code
should do well, no problem here: JavaScript issues are mostly about the
terrible handling of secrets, but there is no secret in verification.
For key pair generation or signature generation, if you *must* have it
done in a JavaScript/browser context, you should consider using the
[Rust](https://github.com/pornin/rust-fn-dsa) or
[C](https://github.com/pornin/c-fn-dsa) implementations compiled for a
WASM target (I have not tried but that should work).

**WARNING (3):** Owing to the limitations of JavaScript, this code
somewhat deviates from the (expected) specification, in that, for
signature generation, it evaluates an exponential with a polynomial with
floating-point coefficients instead of 64-bit fixed-point coefficients.
The result should still be reasonably safe with regard to the security
analysis in the [original Falcon
specification](https://falcon-sign.info/falcon.pdf) but may deviate from
the signatures that would be computed over the same messages and using
the same random seed. Interoperability is maintained, though. To avoid
issues with a private key used with the same seeds in two distinct
implementations (in some rare situations, that could lead to Bad
Things), this code does not provide a "seeded/deterministic" mode; all
signatures are randomized.

## Usage

See [demo.html](demo.html) for a crude demo. This should be loaded from
a Web server (browsers don't like to execute JavaScript from a file, they
need to get it from a Web server). With Python, a simple way to start
a Web server is:

~~~
python3 -m http.server
~~~

launched in the directory. Default bind port is 8000.

The [tests.html](tests.html) file is used to run internal tests. It
loads the implementation and the test code in a weird and hackish way
because the test code needs to access internal functions which are not
part of the exported API.

Normal usage looks as follows:

~~~javascript
// The implementation is a module.
import * as FNDSA from './fndsa.js';

// Generate a key pair. Degree is provided logarithmically, i.e. the
// parameter must be 9 for FN-DSA-512, or 10 for FN-DSA-1024. No other
// value is accepted.
//
// Key pair generation is a bit expensive, you should probably call that
// in a worker thread so as not to freeze the UI.
let kp = FNDSA.keygen(9);

// The signing (private) key is in kp.sign_key; the verifying (public)
// key is in kp.verify_key. Both have type Uint8Array. Sizes are fixed
// for a given degree.

// To sign a message msg:
//
// 'ctx' is a "context string" which should be the overall application
// name; it is for domain separation, and similar to the same concept
// in the ML-DSA algorithm. It can have type string or Uint8Array; if
// provided as a JavaScript string, then it is first encoded with UTF-8.
// The length (in bytes) of the context string must not exceed 255.
//
// 'id' is the ASN.1 DER-encoded OID that qualifies the hash function that
// you used to pre-hash the message. If the message is "raw" (it's not
// a hash value, it is the message itself) then you use ID_RAW.
//
// 'msg' is the message itself (if not pre-hashing) or the hash of the
// message (if pre-hashing). In raw mode, 'msg' can be Uint8Array or
// string; in the latter case, the string is first encoded with UTF-8.
// If pre-hashing is used, then 'msg' must be a Uint8Array instance.
let ctx = 'my great application name';
let id = FNDSA.ID_RAW;
let msg = 'message to sign';
let sig = FNDSA.sign(kp.sign_key, ctx, id, msg);

// Signature has type Uint8Array.

// To verify a signature, use the verifying key.
let r = FNDSA.verify(sig, kp.verify_key, ctx, id, msg);
if (r) {
    // signature is valid
} else {
    // something failed
}
~~~
