# Verify the local candidate

This candidate is private/local; no public download/release or original R5 license
is authorized yet. Signing establishes provenance, not publication permission,
exclusive authorship, legal rights to input data or an OS binary signature.

Known portfolio SSH ED25519 fingerprint:

```text
SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU
```

Obtain that fingerprint through an independently trusted channel before accepting
any key. A key/fingerprint from the same untrusted archive is not independent
identity proof. Never share/request the private key. Check the local public key:

```sh
ssh-keygen -lf SIGNING-PUBLIC-KEY.pub
```

Use OpenSSH file-namespace verification on the exact SHA256SUMS.txt bytes and the
separately supplied SHA256SUMS.txt.sig, with an allowed-signers file containing the
expected public key and the signer identity used by the candidate receipt. Compare
the chosen archive's SHA256 against exactly one filename entry in that verified
manifest before extraction. Do not trust an unsigned matching hash or skip a
missing signature. Use byte input for verification; PowerShell text pipelines can
change bytes. Candidate delivery notes retain the exact commands/key/signature
proof. BUILD-MANIFEST.json binds source commit/tree/RID/localCandidate and every
payload hash, and original-license pending is explicit.

The five public vendored source/license files have exact Git blob/SHA256/size pins
in vendor/integrity-csv/PINS.json and are checked before assessment. Those pins
identify code bytes; they do not authenticate a dataset or its use permissions.
There is no Authenticode/OS-code-signature or clean-machine claim.
