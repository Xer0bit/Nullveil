// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.xer0bit.nullveil;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.ProviderException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM. The key is generated inside the Android Keystore and never leaves it: in the
 * StrongBox security chip when the phone has one, otherwise the trusted execution environment.
 * Every blob is versioned and bound to a context label (GCM associated data), so a blob cannot be
 * moved to another purpose or silently altered. Layout: [version 1 byte][iv 12][ciphertext+tag 16].
 */
final class SecureStore {
    private static final String ALIAS = "nullveil_rules";
    private static final byte VERSION = 1;
    private static final byte[] AAD = "nullveil/rules/v1".getBytes(StandardCharsets.UTF_8);
    private static final int IV_LEN = 12;
    private static String level;

    private SecureStore() {}

    private static KeyGenParameterSpec spec(boolean strongBox) {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256);
        if (strongBox && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true);
        return b.build();
    }

    private static SecretKey key() throws GeneralSecurityException, java.io.IOException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) return (SecretKey) ks.getKey(ALIAS, null);
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        try {
            g.init(spec(true));
            return g.generateKey();
        } catch (ProviderException noStrongBox) { // this phone has no StrongBox chip: use the TEE
            g.init(spec(false));
            return g.generateKey();
        }
    }

    /** base64 blob, or null if the Keystore is unavailable (we then keep nothing on disk). */
    static String encrypt(String plain) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key()); // the Keystore picks a fresh random IV every time
            c.updateAAD(AAD);
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[1 + IV_LEN + ct.length];
            out[0] = VERSION;
            System.arraycopy(c.getIV(), 0, out, 1, IV_LEN);
            System.arraycopy(ct, 0, out, 1 + IV_LEN, ct.length);
            return Base64.encodeToString(out, Base64.NO_WRAP);
        } catch (GeneralSecurityException | java.io.IOException e) {
            return null;
        }
    }

    /** Plain text, or null if the data is missing, altered, from another version, or the key is gone. */
    static String decrypt(String b64) {
        try {
            byte[] in = Base64.decode(b64, Base64.NO_WRAP);
            if (in.length < 1 + IV_LEN + 16 || in[0] != VERSION) return null;
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, in, 1, IV_LEN));
            c.updateAAD(AAD);
            return new String(c.doFinal(in, 1 + IV_LEN, in.length - 1 - IV_LEN), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | java.io.IOException | RuntimeException e) {
            return null;
        }
    }

    /** Where the key really lives, as reported by the phone itself. Cached: it never changes. */
    static synchronized String level() {
        if (level != null) return level;
        try {
            SecretKey k = key();
            KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance(k.getAlgorithm(), "AndroidKeyStore").getKeySpec(k, KeyInfo.class);
            if (Build.VERSION.SDK_INT >= 31) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX: level = "StrongBox security chip"; break;
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: level = "hardware (TEE)"; break;
                    default: level = "software only";
                }
            } else {
                level = info.isInsideSecureHardware() ? "hardware (TEE)" : "software only";
            }
        } catch (GeneralSecurityException | java.io.IOException e) {
            level = "unavailable";
        }
        return level;
    }
}
