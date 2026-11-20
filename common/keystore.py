# SPDX-License-Identifier: Apache-2.0
"""Where a verifier's ML-DSA-65 identity key lives: a 0600 file, or sealed to this machine's TPM 2.0.

TPM 2.0 chips do not implement ML-DSA (the PC's Intel PTT, spec 1.38, has RSA, ECC P-256/BN-256, AES, SHA-1/256), so
the TPM cannot hold and use the signing key itself. What it can do is keep the key unusable anywhere else:

  identity.tpm.json   the ML-DSA-65 secret key encrypted with AES-256-GCM under a random 32-byte key (KEK), and the
                      KEK sealed to the TPM: a keyedhash object with fixedTPM | fixedParent | noDA, created under the
                      owner hierarchy's storage root key (the TCG ECC P-256 SRK template, re-derived from the TPM's
                      owner seed at each start; no persistent handle, no NV index). Optionally its policy requires
                      PCR values (--tpm-pcrs).

The seal is the only copy of the KEK, and the SRK's private part never leaves the TPM, so the files in the state
directory are useless on any other machine, on this machine after a TPM clear, or after a disk theft. The key is
unsealed into the process's memory at start, and anyone who can open /dev/tpmrm0 on this machine (root, group tss)
can unseal it too. It is protection at rest, not against the running machine's administrator.

Commands go over a salted session with AES-128-CFB parameter encryption, so the KEK does not cross the TPM interface in
the clear. The sealed object has noDA, and its auth is empty: no command here can count against dictionary-attack
lockout. Nothing here touches hierarchy auth, PCRs, NV or persistent handles.
"""
import hashlib
import json
import os

SOFTWARE = "software-file"
TPM = "tpm2-sealed"
SK_FILE = "identity.sk"
TPM_FILE = "identity.tpm.json"
FORMAT = "aegis-tpm2-sealed-kek-v1"
SRK_TEMPLATE = "tcg-ecc-p256-srk"   # tpm2_createprimary -C o -G ecc256:aes128cfb -g sha256 (the TCG SRK template)
AAD = b"aegis-tpm2-sealed-identity-v1\0"


class TpmError(RuntimeError):
    pass


def default_tcti():
    return os.environ.get("AEGIS_TPM_TCTI") or "device:/dev/tpmrm0"


# ---- the TPM side (tpm2-pytss, imported only when a TPM is used) ----------------------------------------------------

def _tss():
    try:
        import tpm2_pytss
        return tpm2_pytss
    except ImportError as e:
        raise TpmError("tpm2-pytss is not installed (pip install tpm2-pytss): %s" % e)


def _open(tcti):
    t = _tss()
    tcti = tcti or default_tcti()
    if tcti.startswith("device:"):
        dev = tcti.split(":", 1)[1] or "/dev/tpmrm0"
        if not os.path.exists(dev):
            raise TpmError("no TPM device %s" % dev)
        if not os.access(dev, os.R_OK | os.W_OK):
            raise TpmError("no access to %s (add the user to group tss and log in again)" % dev)
    try:
        return t.ESAPI(tcti)
    except Exception as e:
        raise TpmError("cannot open the TPM (%s): %s" % (tcti, e))


def _prop(ectx, pt):
    t = _tss()
    _, data = ectx.get_capability(t.TPM2_CAP.TPM_PROPERTIES, pt, 1)
    props = data.data.tpmProperties
    return int(props[0].value) if len(props) and int(props[0].property) == int(pt) else 0


def _tpm_facts(ectx):
    """Manufacturer, firmware and the owner-auth bit; refuses a TPM whose owner hierarchy has a password, since this
    code never asks for one (and must not guess: a wrong owner password counts towards lockout)."""
    t = _tss()
    perm = _prop(ectx, t.TPM2_PT.PERMANENT)
    if perm & int(t.TPMA_PERMANENT.OWNERAUTHSET):
        raise TpmError("the TPM's owner hierarchy has a password; refusing to use it")
    man = _prop(ectx, t.TPM2_PT.MANUFACTURER).to_bytes(4, "big").rstrip(b"\0").decode("ascii", "replace")
    fw1, fw2 = _prop(ectx, t.TPM2_PT_FIRMWARE.VERSION_1), _prop(ectx, t.TPM2_PT_FIRMWARE.VERSION_2)
    return {"manufacturer": man, "firmware": "%d.%d.%d.%d" % (fw1 >> 16, fw1 & 0xFFFF, fw2 >> 16, fw2 & 0xFFFF)}


def _srk(ectx):
    """The owner hierarchy's storage root key from the TCG template: the same key every time on the same TPM (it is
    derived from the owner seed), so nothing is stored in the TPM. Returns (handle, name)."""
    t = _tss()
    attrs = (t.TPMA_OBJECT.FIXEDTPM | t.TPMA_OBJECT.FIXEDPARENT | t.TPMA_OBJECT.SENSITIVEDATAORIGIN |
             t.TPMA_OBJECT.USERWITHAUTH | t.TPMA_OBJECT.NODA | t.TPMA_OBJECT.RESTRICTED | t.TPMA_OBJECT.DECRYPT)
    pub = t.TPM2B_PUBLIC.parse("ecc256:aes128cfb", objectAttributes=attrs, nameAlg="sha256")
    handle, out_pub, _, _, _ = ectx.create_primary(t.TPM2B_SENSITIVE_CREATE(), pub, t.ESYS_TR.OWNER)
    return handle, out_pub.get_name().marshal().hex()


def _session(ectx, srk, kind, attrs):
    t = _tss()
    sym = t.TPMT_SYM_DEF(algorithm=t.TPM2_ALG.AES)
    sym.keyBits.aes = 128
    sym.mode.aes = t.TPM2_ALG.CFB
    s = ectx.start_auth_session(srk, t.ESYS_TR.NONE, kind, sym, t.TPM2_ALG.SHA256)
    ectx.trsess_set_attributes(s, attrs)
    return s


def _pcr_selection(pcrs):
    return "sha256:" + ",".join(str(p) for p in pcrs)


def _pcr_policy(ectx, srk, pcrs, trial):
    t = _tss()
    kind = t.TPM2_SE.TRIAL if trial else t.TPM2_SE.POLICY
    s = _session(ectx, srk, kind, t.TPMA_SESSION.CONTINUESESSION | (0 if trial else t.TPMA_SESSION.ENCRYPT))
    ectx.policy_pcr(s, t.TPM2B_DIGEST(), _pcr_selection(pcrs))
    return s


def _check_pcrs(pcrs):
    pcrs = sorted(set(int(p) for p in (pcrs or [])))
    if any(p < 0 or p > 23 for p in pcrs):
        raise ValueError("PCR indexes are 0..23")
    return pcrs


def seal(secret, pcrs=None, tcti=None):
    """Seal up to 128 bytes to this TPM. Returns a JSON-able record (public and private parts, both of them useless
    without this TPM's owner seed)."""
    t = _tss()
    pcrs = _check_pcrs(pcrs)
    if not 0 < len(secret) <= 128:
        raise ValueError("a sealed data object holds 1 to 128 bytes")
    ectx = _open(tcti)
    try:
        facts = _tpm_facts(ectx)
        srk, srk_name = _srk(ectx)
        try:
            attrs = t.TPMA_OBJECT.FIXEDTPM | t.TPMA_OBJECT.FIXEDPARENT | t.TPMA_OBJECT.NODA
            policy = b""
            if pcrs:
                trial = _pcr_policy(ectx, srk, pcrs, trial=True)
                policy = bytes(ectx.policy_get_digest(trial))
                ectx.flush_context(trial)
            else:
                attrs |= t.TPMA_OBJECT.USERWITHAUTH
            pub = t.TPM2B_PUBLIC(t.TPMT_PUBLIC(type=t.TPM2_ALG.KEYEDHASH, nameAlg=t.TPM2_ALG.SHA256,
                                               objectAttributes=attrs, authPolicy=policy))
            pub.publicArea.parameters.keyedHashDetail.scheme.scheme = t.TPM2_ALG.NULL
            sens = t.TPM2B_SENSITIVE_CREATE(t.TPMS_SENSITIVE_CREATE(data=t.TPM2B_SENSITIVE_DATA(secret)))
            s = _session(ectx, srk, t.TPM2_SE.HMAC, t.TPMA_SESSION.CONTINUESESSION | t.TPMA_SESSION.DECRYPT)
            try:
                priv, out_pub, _, _, _ = ectx.create(srk, sens, pub, session1=s)
            finally:
                ectx.flush_context(s)
        finally:
            ectx.flush_context(srk)
    except t.TSS2_Exception as e:
        raise TpmError("TPM refused to seal: %s" % e)
    finally:
        ectx.close()
    return {"srk_template": SRK_TEMPLATE, "srk_name": srk_name, "pcrs": _pcr_selection(pcrs) if pcrs else "",
            "public": out_pub.marshal().hex(), "private": priv.marshal().hex(), "tpm": facts}


def unseal(sealed, tcti=None, check_srk=True):
    """The sealed bytes, or TpmError. check_srk=False skips the friendly "not this TPM" test, so a test can show that
    the TPM itself refuses a blob from another TPM."""
    t = _tss()
    if sealed.get("srk_template") != SRK_TEMPLATE:
        raise TpmError("unknown parent template %r" % sealed.get("srk_template"))
    ectx = _open(tcti)
    try:
        _tpm_facts(ectx)
        srk, srk_name = _srk(ectx)
        try:
            if check_srk and srk_name != sealed["srk_name"]:
                raise TpmError("sealed to another TPM (storage root key %s..., this TPM has %s...), or this TPM was "
                               "cleared since" % (sealed["srk_name"][:16], srk_name[:16]))
            priv, _ = t.TPM2B_PRIVATE.unmarshal(bytes.fromhex(sealed["private"]))
            pub, _ = t.TPM2B_PUBLIC.unmarshal(bytes.fromhex(sealed["public"]))
            obj = ectx.load(srk, priv, pub)
            try:
                if sealed.get("pcrs"):
                    s = _pcr_policy(ectx, srk, [int(p) for p in sealed["pcrs"].split(":", 1)[1].split(",")], False)
                else:
                    s = _session(ectx, srk, t.TPM2_SE.HMAC, t.TPMA_SESSION.CONTINUESESSION | t.TPMA_SESSION.ENCRYPT)
                try:
                    return bytes(ectx.unseal(obj, session1=s))
                finally:
                    ectx.flush_context(s)
            finally:
                ectx.flush_context(obj)
        finally:
            ectx.flush_context(srk)
    except t.TSS2_Exception as e:
        raise TpmError("TPM refused to unseal: %s" % e)
    finally:
        ectx.close()


def tpm_status(tcti=None):
    """(usable, reason, facts) without creating anything."""
    try:
        ectx = _open(tcti)
    except TpmError as e:
        return False, str(e), {}
    try:
        return True, "", _tpm_facts(ectx)
    except TpmError as e:
        return False, str(e), {}
    except Exception as e:
        return False, "TPM did not answer: %s" % e, {}
    finally:
        ectx.close()


# ---- the identity key -----------------------------------------------------------------------------------------------

def _aead(kek):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(kek)


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def save(state, sk, pk, store=SOFTWARE, pcrs=None, tcti=None):
    """Store the identity secret key. Returns the record's description of where it lives:
    {"key_store": ..., "tpm": {...}} (tpm only for the TPM store). With the TPM store, the secret key is never written
    to disk unencrypted and no identity.sk exists."""
    if store == SOFTWARE:
        _replace(state, SK_FILE, sk)
        return {"key_store": SOFTWARE}
    if store != TPM:
        raise ValueError("unknown key store %r" % store)
    kek, nonce = os.urandom(32), os.urandom(12)
    sealed = seal(kek, pcrs, tcti)       # first: if the TPM refuses, the old identity is still there
    ct = _aead(kek).encrypt(nonce, sk, AAD + hashlib.sha256(pk).digest())
    rec = dict(sealed, v=1, format=FORMAT, pk_sha256=hashlib.sha256(pk).hexdigest(), nonce=nonce.hex(),
               ciphertext=ct.hex())
    _replace(state, TPM_FILE, json.dumps(rec, indent=1).encode())
    return {"key_store": TPM, "tpm": dict(sealed["tpm"], srk_name=sealed["srk_name"], pcrs=sealed["pcrs"])}


def _replace(state, name, data):
    """Write the new key file, then remove the other kind (load prefers identity.sk, so it must not linger)."""
    _write_private(os.path.join(state, name + ".new"), data)
    os.replace(os.path.join(state, name + ".new"), os.path.join(state, name))
    other = TPM_FILE if name == SK_FILE else SK_FILE
    try:
        os.unlink(os.path.join(state, other))
    except FileNotFoundError:
        pass


def stored_where(state):
    if os.path.exists(os.path.join(state, SK_FILE)):
        return SOFTWARE
    if os.path.exists(os.path.join(state, TPM_FILE)):
        return TPM
    return None


def load(state, pk=None, tcti=None):
    """(secret key, measurement claims). identity.sk wins if both exist (an older software identity)."""
    where = stored_where(state)
    if where == SOFTWARE:
        with open(os.path.join(state, SK_FILE), "rb") as f:
            return f.read(), {"key_store": SOFTWARE}
    if where is None:
        raise FileNotFoundError("no %s or %s in %s" % (SK_FILE, TPM_FILE, state))
    with open(os.path.join(state, TPM_FILE)) as f:
        rec = json.load(f)
    if rec.get("format") != FORMAT:
        raise TpmError("%s: unknown format %r" % (TPM_FILE, rec.get("format")))
    pk = pk if pk is not None else b""
    if pk and hashlib.sha256(pk).hexdigest() != rec["pk_sha256"]:
        raise TpmError("%s holds the key of another identity" % TPM_FILE)
    kek = unseal(rec, tcti)
    try:
        from cryptography.exceptions import InvalidTag
        sk = _aead(kek).decrypt(bytes.fromhex(rec["nonce"]), bytes.fromhex(rec["ciphertext"]),
                                AAD + bytes.fromhex(rec["pk_sha256"]))
    except InvalidTag:
        raise TpmError("%s: the encrypted key does not match the sealed key (file altered)" % TPM_FILE)
    claims = {"key_store": TPM, "key_store_tpm_srk_name": rec["srk_name"]}
    if rec.get("pcrs"):
        claims["key_store_tpm_pcrs"] = rec["pcrs"]
    return sk, claims
