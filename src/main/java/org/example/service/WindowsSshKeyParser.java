package org.example.service;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class WindowsSshKeyParser {
    public static RSAPublicKeySpec createKeySpecFromSshRsaPublicKey(String sshPublicKeyString) throws Exception {
        // 1. Extract Base64 (assuming standard OpenSSH format)
        String[] parts = sshPublicKeyString.split(" ");
        String base64Key = parts[1];

        // 2. Base64 Decode
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);

        // 3. Parse Binary Data
        ByteBuffer buffer = ByteBuffer.wrap(decodedKey);

        // Read "ssh-rsa" string (skip it for modulus extraction)
        int typeLength = buffer.getInt();
        byte[] typeBytes = new byte[typeLength];
        buffer.get(typeBytes); // "ssh-rsa"

        // Read public exponent
        int exponentLength = buffer.getInt();
        byte[] exponentBytes = new byte[exponentLength];
        buffer.get(exponentBytes);
        BigInteger publicExponent = new BigInteger(exponentBytes);

        // Read modulus
        int modulusLength = buffer.getInt();
        byte[] modulusBytes = new byte[modulusLength];
        buffer.get(modulusBytes);
        BigInteger modulus = new BigInteger(modulusBytes);

        // 4. Construct and return RSAPublicKeySpec
        return new RSAPublicKeySpec(modulus, publicExponent);
    }
}
