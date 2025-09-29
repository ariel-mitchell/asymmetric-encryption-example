package org.example;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

import static org.example.service.PrivateKeyReader.readPrivateKey;
import static org.example.service.PublicKeyReader.readPublicKey;

public class AsymmetricEncryptionExample {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        while(true) {
            System.out.println("SECRET SPY TEAM COMMUNICATION SYSTEM");
            System.out.println("======================================");
            System.out.println("1. Encrypt a message");
            System.out.println("2. Decrypt a message");
            System.out.println("3. Quit");

            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();

            if (choice == 1) {
                encryptMessage();
            } else if (choice == 2) {
                decryptMessage();
            } else if (choice == 3) {
                break;
            } else {
                System.out.println("Invalid choice");
            }
        }
    }

    public static void encryptMessage() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter path to target user's public key file: ");
        String publicKeyPath = scanner.nextLine();
        System.out.println("Enter message to encrypt: ");
        String message = scanner.nextLine();

        try {
            // Read the public key
            PublicKey publicKey = readPublicKey(publicKeyPath);

            // Encrypt the message
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(message.getBytes());

            // Print the encrypted message
            System.out.println("Encrypted message:");
            System.out.println(DatatypeConverter.printHexBinary(encrypted));
        } catch (Exception e) {
            System.out.println("Error encrypting message: " + e.getMessage());
        }
    }

    public static void decryptMessage() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter path to your private key file: ");
        String privateKeyPath = scanner.nextLine();
        System.out.println("Enter encrypted message: ");
        String encryptedMessage = scanner.nextLine();

        try {
            // Read the private key
            PrivateKey privateKey = readPrivateKey(privateKeyPath);

            // Decrypt the message
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = cipher.doFinal(DatatypeConverter.parseHexBinary(encryptedMessage));

            // Print the decrypted message
            System.out.println("Decrypted message:");
            System.out.println(new String(decrypted));
        } catch (Exception e) {
            System.out.println("Error decrypting message: " + e.getMessage());
        }
    }
}