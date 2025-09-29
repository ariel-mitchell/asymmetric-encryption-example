package org.example.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class PrivateKeyReader {

    public static PrivateKey readPrivateKey(String filePath)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // 1. Read the key data from the file
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));

        // 2. Remove PEM headers and decode Base64
        String keyContent = new String(keyBytes);
        keyContent = keyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", ""); // Remove whitespace
        byte[] decodedKey = Base64.getDecoder().decode(keyContent);

//        if (OpenSSH)) {
//            TODO: Create parser to handle Windows-created private key OR explore using a library (Bouncy Castle).
//        }

        // 3. Create a PKCS8EncodedKeySpec
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);

        // 4. Obtain a KeyFactory instance
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // 5. Generate the PrivateKey object
        return keyFactory.generatePrivate(keySpec);
    }
}