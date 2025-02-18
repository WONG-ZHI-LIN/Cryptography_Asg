import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.math.BigInteger;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class CryptographyCLI {

    // Playfair Cipher Encryption
    public static String playfairCipherEncrypt(String text, String key) {
        text = text.replaceAll("[^A-Za-z]", "").toUpperCase().replace("J", "I");
        key = key.replaceAll("[^A-Za-z]", "").toUpperCase().replace("J", "I");

        char[][] matrix = generatePlayfairMatrix(key);
        StringBuilder encryptedText = new StringBuilder();
        StringBuilder formattedText = new StringBuilder();

        long startTime = System.nanoTime(); // Start timing

        // Format text: prevent identical letter pairs & ensure even length
        for (int i = 0; i < text.length(); i++) {
            formattedText.append(text.charAt(i));
            if (i + 1 < text.length() && text.charAt(i) == text.charAt(i + 1)) {
                formattedText.append('X'); // Insert 'X' for duplicate letters
            }
        }
        if (formattedText.length() % 2 != 0)
            formattedText.append('X'); // Ensure even length

        System.out.println("Formatted Text for Playfair Encryption: " + formattedText.toString());

        // Playfair Encryption
        for (int i = 0; i < formattedText.length(); i += 2) {
            char a = formattedText.charAt(i), b = formattedText.charAt(i + 1);
            int[] posA = findPosition(matrix, a), posB = findPosition(matrix, b);

            if (posA[0] == -1 || posB[0] == -1) {
                System.err.println("Error: Character not found in Playfair Matrix.");
                return null;
            }

            if (posA[0] == posB[0]) { // Same row: shift right
                encryptedText.append(matrix[posA[0]][(posA[1] + 1) % 5])
                        .append(matrix[posB[0]][(posB[1] + 1) % 5]);
            } else if (posA[1] == posB[1]) { // Same column: shift down
                encryptedText.append(matrix[(posA[0] + 1) % 5][posA[1]])
                        .append(matrix[(posB[0] + 1) % 5][posB[1]]);
            } else { // Rectangle swap
                encryptedText.append(matrix[posA[0]][posB[1]])
                        .append(matrix[posB[0]][posA[1]]);
            }
        }

        long endTime = System.nanoTime(); // End timing
        long timeElapsed = (endTime - startTime) / 1_000_000; // Convert nanoseconds to milliseconds

        System.out.println("Encrypted Text: " + encryptedText.toString());
        System.out.println("Encryption Time: " + timeElapsed + " ms");
        return encryptedText.toString();
    }

    // Playfair Cipher Matrix Generation
    private static char[][] generatePlayfairMatrix(String key) {
        String alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // Merged 'I' and 'J'
        StringBuilder matrixKey = new StringBuilder();
        boolean[] used = new boolean[26]; // A-Z, but 'J' will be merged

        // Add key to matrix (removing duplicates)
        for (char c : key.toUpperCase().toCharArray()) {
            if (c == 'J')
                c = 'I'; // Treat 'J' as 'I'
            if (c >= 'A' && c <= 'Z' && !used[c - 'A']) {
                matrixKey.append(c);
                used[c - 'A'] = true;
            }
        }

        // Add remaining letters from alphabet
        for (char c : alphabet.toCharArray()) {
            if (!used[c - 'A']) {
                matrixKey.append(c);
                used[c - 'A'] = true;
            }
        }

        // Populate the 5x5 matrix
        char[][] matrix = new char[5][5];
        int index = 0;
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                matrix[row][col] = matrixKey.charAt(index++);
            }
        }

        return matrix;
    }

    private static int[] findPosition(char[][] matrix, char c) {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                if (matrix[i][j] == c) {
                    return new int[] { i, j };
                }
            }
        }
        return new int[] { -1, -1 }; // Return an invalid position instead of null
    }

    // Playfair Cipher Decryption
    public static String playfairCipherDecrypt(String text, String key) {
        char[][] matrix = generatePlayfairMatrix(key);

        // Ensure the text length is even
        if (text.length() % 2 != 0) {
            System.err.println("Error: Ciphertext length is not even. Possible corruption.");
            return null;
        }

        Instant startTime = Instant.now(); // Start timing
        String decryptedText = processPlayfair(text, matrix, false);
        Instant endTime = Instant.now(); // End timing
        long timeElapsed = Duration.between(startTime, endTime).toMillis(); // Calculate time in milliseconds
        System.out.println("Decryption Output: " + decryptedText);
        System.out.println("Time taken: " + timeElapsed + " ms");

        return decryptedText;
    }

    private static String processPlayfair(String text, char[][] matrix, boolean encrypt) {
        StringBuilder result = new StringBuilder();
        int shift = encrypt ? 1 : -1; // Right for encryption, left for decryption

        for (int i = 0; i < text.length(); i += 2) {
            char a = text.charAt(i), b = text.charAt(i + 1);
            int[] posA = findPosition(matrix, a), posB = findPosition(matrix, b);

            // SAFETY CHECK: Ensure valid character positions
            if (posA[0] == -1 || posB[0] == -1) {
                System.err.println("Error: One or both characters not found in Playfair Matrix.");
                return null;
            }

            if (posA[0] == posB[0]) { // Same row: shift LEFT for decryption
                result.append(matrix[posA[0]][(posA[1] + shift + 5) % 5])
                        .append(matrix[posB[0]][(posB[1] + shift + 5) % 5]);
            } else if (posA[1] == posB[1]) { // Same column: shift UP for decryption
                result.append(matrix[(posA[0] + shift + 5) % 5][posA[1]])
                        .append(matrix[(posB[0] + shift + 5) % 5][posB[1]]);
            } else { // Rectangle swap
                result.append(matrix[posA[0]][posB[1]])
                        .append(matrix[posB[0]][posA[1]]);
            }
        }

        String decryptedText = result.toString();

        // **Fix Artificial 'X' Removal**
        decryptedText = removeArtificialX(decryptedText);

        return decryptedText;
    }

    // Improved Artificial 'X' Removal
    private static String removeArtificialX(String text) {
        StringBuilder cleanText = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            // Avoid removing actual 'X' in words like "TEXT"
            if (i > 0 && text.charAt(i) == 'X' && i < text.length() - 1
                    && text.charAt(i - 1) == text.charAt(i + 1)) {
                continue; // Skip the artificial 'X'
            }
            cleanText.append(text.charAt(i));
        }

        // **Remove trailing 'X' if it was added artificially**
        if (cleanText.length() > 0 && cleanText.charAt(cleanText.length() - 1) == 'X') {
            cleanText.deleteCharAt(cleanText.length() - 1);
        }

        return cleanText.toString();
    }

    // Rail Fence Cipher Encryption (Fixed Zigzag Implementation)
    public static String railFenceEncrypt(String text) {
        int depth = 3;
        if (text.length() <= 1)
            return text;

        Instant startTime = Instant.now(); // Start timing

        StringBuilder[] rails = new StringBuilder[depth];
        for (int i = 0; i < depth; i++)
            rails[i] = new StringBuilder();

        int row = 0, direction = 1;
        for (char c : text.toCharArray()) {
            rails[row].append(c);
            row += direction;
            if (row == 0 || row == depth - 1)
                direction *= -1;
        }

        StringBuilder encryptedText = new StringBuilder();
        for (StringBuilder sb : rails)
            encryptedText.append(sb);

        Instant endTime = Instant.now(); // End timing
        long timeElapsed = Duration.between(startTime, endTime).toMillis(); // Calculate time in milliseconds
        System.out.println("Encrypted Text: " + encryptedText.toString());
        System.out.println("Time taken: " + timeElapsed + " ms");
        return encryptedText.toString();
    }

    // Rail Fence Cipher Decryption
    public static String railFenceDecrypt(String text) {
        int depth = 3;
        if (text.length() <= 1)
            return text;

        Instant startTime = Instant.now(); // Start timing

        char[] decryptedText = new char[text.length()];
        int[] pattern = new int[text.length()];
        int row = 0, direction = 1;

        // Step 1: Determine the zig-zag pattern positions
        for (int i = 0; i < text.length(); i++) {
            pattern[i] = row;
            row += direction;
            if (row == 0 || row == depth - 1)
                direction *= -1;
        }

        // Step 2: Count characters in each row
        int[] rowCounts = new int[depth];
        for (int r : pattern)
            rowCounts[r]++;

        // Step 3: Fill rows with correct characters
        StringBuilder[] rows = new StringBuilder[depth];
        for (int i = 0; i < depth; i++)
            rows[i] = new StringBuilder();

        int index = 0;
        for (int i = 0; i < depth; i++) {
            for (int j = 0; j < rowCounts[i]; j++) {
                rows[i].append(text.charAt(index++));
            }
        }

        // Step 4: Read characters from zig-zag pattern to decrypt
        row = 0;
        direction = 1;
        index = 0;
        for (int i = 0; i < text.length(); i++) {
            decryptedText[i] = rows[pattern[i]].charAt(0);
            rows[pattern[i]].deleteCharAt(0);
        }

        Instant endTime = Instant.now(); // End timing
        long timeElapsed = Duration.between(startTime, endTime).toMillis(); // Calculate time in milliseconds
        System.out.println("Time taken: " + timeElapsed + " ms");
        System.out.println("Decrypted Text: " + new String(decryptedText));
        return new String(decryptedText);
    }

    // Product Cipher (Playfair + Rail Fence)
    public static String productCipherEncrypt(String text, String key) {
        String playfairEncrypted = playfairCipherEncrypt(text, key);
        System.out.println("After Playfair Cipher: " + playfairEncrypted);

        String railFenceEncrypted = railFenceEncrypt(playfairEncrypted);
        System.out.println("After Rail Fence Cipher: " + railFenceEncrypted);

        return railFenceEncrypted;
    }

    // Product Cipher Decryption
    public static String productCipherDecrypt(String text, String key) {
        String railFenceDecrypted = railFenceDecrypt(text);
        System.out.println("After Rail Fence Decryption: " + railFenceDecrypted);

        String playfairDecrypted = playfairCipherDecrypt(railFenceDecrypted, key);
        System.out.println("After Playfair Decryption: " + playfairDecrypted);

        return playfairDecrypted;
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\nWelcome to Cryptography CLI Tool");
            System.out.println("1. Playfair Cipher");
            System.out.println("2. Rail Fence Cipher");
            System.out.println("3. Product Cipher (Playfair + Rail Fence)");
            System.out.println("4. RSA & AES HYbrid Encryption");
            System.out.println("5. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1:
                    playfairMenu(scanner);
                    break;
                case 2:
                    railFenceMenu(scanner);
                    break;
                case 3:
                    productCipherMenu(scanner);
                    break;
                case 4:
                    try {
                        ManualRSAEncryption.performHybridEncryption(scanner);
                    } catch (Exception e) {
                        System.err.println("An error occurred during hybrid encryption: " + e.getMessage());
                    }
                    break;

                case 5:
                    System.out.println("Exiting...");
                    break;
                default:
                    System.out.println("Invalid choice, try again.");
            }
        }
    }

    private static void playfairMenu(Scanner scanner) {
        while (true) {
            System.out.println("\nPlayfair Cipher");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. Back");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            if (choice == 3)
                return;

            System.out.print("Enter text: ");
            String text = scanner.nextLine();
            System.out.print("Enter Playfair key: ");
            String key = scanner.nextLine();

            if (choice == 1) {
                System.out.println("Encrypted: " + playfairCipherEncrypt(text, key));
            } else if (choice == 2) {
                System.out.println("Decrypted: " + playfairCipherDecrypt(text, key));
            } else {
                System.out.println("Invalid choice, try again.");
            }
        }
    }

    private static void railFenceMenu(Scanner scanner) {
        while (true) {
            System.out.println("\nRail Fence Cipher");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. Back");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            if (choice == 3)
                return;

            System.out.print("Enter text: ");
            String text = scanner.nextLine();

            if (choice == 1) {
                System.out.println("Encrypted: " + railFenceEncrypt(text));
            } else if (choice == 2) {
                System.out.println("Decrypted: " + railFenceDecrypt(text));
            } else {
                System.out.println("Invalid choice, try again.");
            }
        }
    }

    private static void productCipherMenu(Scanner scanner) {
        while (true) {
            System.out.println("\nProduct Cipher (Playfair + Rail Fence)");
            System.out.println("1. Encrypt");
            System.out.println("2. Decrypt");
            System.out.println("3. Back");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine();

            if (choice == 3)
                return;

            System.out.print("Enter text: ");
            String text = scanner.nextLine();
            System.out.print("Enter Playfair key: ");
            String key = scanner.nextLine();

            if (choice == 1) {
                System.out.println("Encrypted: " + productCipherEncrypt(text, key));
            } else if (choice == 2) {
                System.out.println("Decrypted: " + productCipherDecrypt(text, key));
            } else {
                System.out.println("Invalid choice, try again.");
            }
        }
    }
}

// RSA and AES Hybrid Encryption Class
class ManualRSAEncryption {
    private static final int BIT_LENGTH = 1024;
    private static final SecureRandom random = new SecureRandom();
    private BigInteger n, e, d;

    public ManualRSAEncryption() {
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH / 2, random);
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        e = new BigInteger("65537");
        d = e.modInverse(phi);
    }

    public BigInteger encryptRSA(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decryptRSA(BigInteger ciphertext) {
        return ciphertext.modPow(d, n);
    }

    public BigInteger getPublicKey() {
        return e;
    }

    public BigInteger getModulus() {
        return n;
    }

    // AES Encryption Method
    private static byte[] encryptAES(byte[] plaintext, SecretKey key) throws Exception {
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes); // Use random IV for security
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encrypted = cipher.doFinal(plaintext);

        // Combine IV and Ciphertext
        byte[] combined = new byte[ivBytes.length + encrypted.length];
        System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
        System.arraycopy(encrypted, 0, combined, ivBytes.length, encrypted.length);
        return combined;
    }

    // AES Decryption Method (with input validation)
    private static byte[] decryptAES(byte[] ciphertext, SecretKey key) throws Exception {
        if (ciphertext.length < 16) {
            throw new IllegalArgumentException("Ciphertext too short, cannot extract IV.");
        }

        byte[] iv = new byte[16];
        System.arraycopy(ciphertext, 0, iv, 0, iv.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return cipher.doFinal(ciphertext, iv.length, ciphertext.length - iv.length);
    }

    // Fix RSA-AES Key Exchange Conversion Issue
    private static SecretKey generateAESKey() {
        try {
            javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("AES");
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error generating AES key", e);
        }
    }

    // Change from private to public to allow calling from main()
    public static void performHybridEncryption(java.util.Scanner scanner) throws Exception {
        System.out.println("\n======================================================");
        System.out.println(" SIMULATING PERSON A & B COMMUNICATION USING RSA & AES (CBC) ");
        System.out.println("========================================================");

        // Generate RSA Keys
        ManualRSAEncryption rsa = new ManualRSAEncryption();
        BigInteger publicKeyB = rsa.getPublicKey();
        BigInteger modulusB = rsa.getModulus();

        // Generate AES Key
        SecretKey aesKey = generateAESKey();
        String aesKeyBase64 = Base64.getEncoder().encodeToString(aesKey.getEncoded());
        BigInteger aesKeyBigInt = new BigInteger(1, aesKeyBase64.getBytes());
        System.out.println("\n[Person A] AES Key (Base64): " + aesKeyBase64);

        // Encrypt AES Key using RSA
        BigInteger encryptedAESKey = aesKeyBigInt.modPow(publicKeyB, modulusB);
        System.out.println("[Person A] Encrypted AES Key: " + encryptedAESKey);

        // Decrypt AES Key using RSA
        BigInteger decryptedAESKeyBigInt = encryptedAESKey.modPow(rsa.d, rsa.n);
        byte[] decryptedBytes = decryptedAESKeyBigInt.toByteArray();
        String decryptedAESBase64 = new String(decryptedBytes);
        SecretKey originalAESKey = new SecretKeySpec(Base64.getDecoder().decode(decryptedAESBase64), "AES");
        System.out.println("[Person B] Decrypted AES Key (Base64): " + decryptedAESBase64);

        // Encrypt Message Using AES
        System.out.print("\n[Person A] Enter message to encrypt: ");
        String message = scanner.nextLine();
        byte[] encryptedMessage = encryptAES(message.getBytes(), originalAESKey);
        System.out.println(
                "[Person A] Encrypted Message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Decrypt the Message
        byte[] decryptedMessage = decryptAES(encryptedMessage, originalAESKey);
        System.out.println("[Person B] Decrypted Message: " + new String(decryptedMessage));

        simulateBitError(encryptedMessage, originalAESKey.getEncoded());
    }

    // Simulating Bit Error in Ciphertext
    private static void simulateBitError(byte[] ciphertext, byte[] keyBytes) {
        byte[] corruptedCiphertext = ciphertext.clone();
        int blockSize = 16; // AES block size
        int startCorrupt = 4; // Corrupting from the 5th byte onward

        System.out.println("\n===================================");
        System.out.println(" SIMULATING BIT ERROR IN CIPHERTEXT...");
        System.out.println("=====================================\n");

        // Introduce bit errors across one full AES block
        for (int i = startCorrupt; i < startCorrupt + blockSize && i < corruptedCiphertext.length; i++) {
            corruptedCiphertext[i] ^= 0xFF; // Flip all bits in this byte
        }

        System.out
                .println("[Person A] Original Ciphertext (Base64): " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println(
                "[Person B] Corrupted Ciphertext (Base64): " + Base64.getEncoder().encodeToString(corruptedCiphertext));
        System.out
                .println("[Person B] Bit error introduced in block starting at byte position: " + startCorrupt + "\n");

        System.out.println("Explanation: AES encryption works in blocks (16 bytes each).");
        System.out.println("Flipping bits in a block will cause full corruption in that block.");
        System.out.println("This results in garbled output or total decryption failure.\n");

        // Convert the AES key bytes to a SecretKey object
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // Decrypt the corrupted message
        try {
            byte[] corruptedDecryption = decryptAES(corruptedCiphertext, secretKey);
            System.out.println(
                    "[Person B] Decrypted Message (With Bit Error): " + new String(corruptedDecryption) + "\n");
        } catch (Exception e) {
            System.out.println("[Person B] Decryption failed due to bit errors. The recovered message is unreadable.");
        }

        System.out.println("====================================\n");
    }
}