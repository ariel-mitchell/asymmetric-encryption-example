package org.example.utils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.example.utils.WindowsSshKeyParser.createKeySpecFromSshRsaPublicKey;

public class PublicKeyReader {

    public static PublicKey readPublicKey(String filePath) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));

        // KeyFactory can handle multiple spec types
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Handle PEM, PUB, and DER formats
        if (filePath.endsWith(".pem")) {
            // Remove PEM headers and decode Base64
            String EMAIL_PATTERN = "([^.@\\s]+)(\\.[^.@\\s]+)*@([^.@\\s]+\\.)+([^.@\\s]+)";
            String pemContent = new String(keyBytes).replace("-----BEGIN PUBLIC KEY-----", "")
                                                    .replace("-----END PUBLIC KEY-----", "")
                                                    .replaceAll("\\s", "")
                                                    .replaceAll(EMAIL_PATTERN, "");

            byte[] decodedKey = Base64.getDecoder().decode(pemContent);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            return keyFactory.generatePublic(keySpec);
        } else if (filePath.endsWith(".pub")) {
            // Use WindowsSshKeyParser class to parse data and create RSAPublicKeySpec
            String pubContent = new String(keyBytes);
            RSAPublicKeySpec keySpec = createKeySpecFromSshRsaPublicKey(pubContent);
            return keyFactory.generatePublic(keySpec);
        } else {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        }
     }
}
