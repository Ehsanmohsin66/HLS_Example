using System.Security.Cryptography;

namespace AES
{
    public class AES_Encryption
    {
        static void Main()
        {

            byte[] key = HexStringToByteArray("000102030405060708090A0B0C0D0E0F");
            byte[] authKey = HexStringToByteArray("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF");

            byte[] encryptedData = HexStringToByteArray("F96F7850A8B5CBF0E5CA4B9ACFC45E785C3BE0ECBA11E061353E669B4590E4");
            byte[] tag = HexStringToByteArray("9C227940F6CC4EF2FCCC15B7");
            byte[] nonce = HexStringToByteArray("54504C000000000001234567");

            byte[] decryptedData = AesGcmDecrypt(encryptedData, key, nonce, authKey, tag);

            Console.WriteLine(Convert.ToHexString(decryptedData));

            if (Convert.ToHexString(decryptedData).ToUpper() == "01011000112233445566778899AABBCCDDEEFF0000065F1F0400007E1F04B0")
            {
                Console.WriteLine("Decrypted Data Got Matched");
            }
        }

        static void AesGcmEncrypt(byte[] plainText, byte[] key, byte[] nonce, byte[] authKey, out byte[] cipherText, out byte[] authTag)
        {
            using (AesGcm aesGcm = new AesGcm(key))
            {
                cipherText = new byte[plainText.Length];
                authTag = new byte[12];
                aesGcm.Encrypt(nonce, plainText, cipherText, authTag, authKey);
            }
        }

        static byte[] AesGcmDecrypt(byte[] cipherText, byte[] key, byte[] nonce, byte[] authKey, byte[] authTag)
        {
            byte[] decryptedText = new byte[cipherText.Length];
            using (AesGcm aesGcm = new AesGcm(key))
            {
                aesGcm.Decrypt(nonce, cipherText, authTag, decryptedText, authKey);
            }
            return decryptedText;
        }

        static byte[] HexStringToByteArray(string hex)
        {
            return Convert.FromHexString(hex);
        }
    }
}