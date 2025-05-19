using ConsoleApp4;

using System;
using System.Security.Cryptography;
using System.Text;

public class StoreKey
{
    public static int KeySize = 2048;
  
    public static void Main()
    {

         ImportKeyFromEncryptedString("P@ssword12311111", "DWIzFkO22qfVMgx2fIsxOXnwz10pRuZf");

        try
        {
            var test = DecryptText("no3X4qnPmwe+3fT+OfLvh8YFzKdHu12L0QZ+gnu3qW1wMzgAMtNdgvAQcjMbLxK7Ym1gkra2o6iBBZQOSNZTnGIHVloI7ZLVUxSHyZ4dPWrkqiFT9ylcIpMqM15y4bgJr7MbU2arai6gXD+JBatPPjptTwB79K185WerSB6emBiqWjRdMgHyzrtumhqZp7Ag7+nyljENe0PAzz8baICOlr3PMaGYLvwv1T929+lzZhz4L08D07mhc4EzC54YBrpXyJppEDpvlrxnxATWr+oA5F5WFPDN8wBuvTwjaTqsbdKSHcfDBEFgzbySuKnzImkGJB64VZ4cxpVq94ZJ9MdSIg==");
            // Create a key and save it in a container.
            //GenKey_SaveInContainer("MyKeyContainer");

            // Retrieve the key from the container.
            //  GetKeyFromContainer("ConfigContainer");

            //  GetKeyFromContainer("BBLConfigKeyContainer");

            // Delete the key from the container.
            //DeleteKeyFromContainer("MyKeyContainer");

            // Create a key and save it in a container.
            //GenKey_SaveInContainer("MyKeyContainer");

            // Delete the key from the container.
            // DeleteKeyFromContainer("MyKeyContainer");

            Console.ReadLine();
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
        }
    }

    private static void ImportKeyFromEncryptedString(string password, string encryptedData)
    {
        try
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(encryptedData))
                throw new ArgumentNullException(nameof(encryptedData));

            ImportKey(password, encryptedData);
        }
        catch (Exception ex)
        {
          
            throw;
        }
    }

    private static string DecryptText(string text)
    {
        string plain = ""; //plain text			
        byte[] cipherBytes = Convert.FromBase64String(text);

        //Cut the cypher into blocks
        int size = KeySize / 8;
        int block = cipherBytes.Length / size;
        int index = 0;

        var cipherBlocks = new List<byte[]>();

        while (index < block)
        {
            int start = 0;
            byte[] cBlock = new byte[size];
            for (int i = index * size; i < (index + 1) * size; i++)
            {
                cBlock[start] = cipherBytes[i];
                start++;
            }
            cipherBlocks.Add(cBlock);
            index++;
        }

        //Decrypt each block
        foreach (var cBlock in cipherBlocks)
        {
            var plainBytes = Decrypt(cBlock);
            plain += Encoding.UTF8.GetString(plainBytes);
        }
        return plain;
    }

    private static byte[] Decrypt(byte[] plainBytes)
    {
        using var rsa = GetCryptoServiceProvider();



        return rsa.Decrypt(plainBytes, RSAEncryptionPadding.Pkcs1);


    }

    private static RSA GetCryptoServiceProvider()
    {
        if (OperatingSystem.IsWindows())
        {
            var cspParams = new CspParameters
            {
                KeyContainerName = "KeyTe",
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            RSACryptoServiceProvider.UseMachineKeyStore = true;
            var rsa = new RSACryptoServiceProvider(
                KeySize,
                cspParams)
            {
                PersistKeyInCsp = true
            };
            return rsa;
        }

        throw new InvalidOperationException("OnPrem encryption provider requires installation on a Windows Environment to utilize RSA Cryptographic Services.");
    }

    private static readonly byte[] InitialisationVector = { 0x03, 0x15, 0x6E, 0x33, 0x2F, 0x80, 0x0F, 0xA1 };
    private static readonly byte[] Salt = new byte[] { 0xFF, 0x00, 0x50, 0x78, 0x6F, 0x06, 0xBA, 0xA0 };

    /// <summary>
    /// Import the public key and private key pair from an XML string.
    /// </summary>
    /// <param name="xmlString">The XML String of the private key to import</param>
    private static void ImportKey(string xmlString)
    {
        var rsa = GetCryptoServiceProvider();
        rsa.FromXmlString(xmlString);
    }

    /// <summary>
    /// Takes a KeyStore in the form of an encrypted string, decrypts it, and imports to KeyContainer.
    /// </summary>
    /// <param name="password">The plain text password to decrypt the keystore.</param>
    /// <param name="encryptedData">The encrypted data read from the KeyStore.</param>
    private static void ImportKey(string password, string encryptedData)
    {
        // Try to decrypt
        var bytes = Convert.FromBase64String(encryptedData);

        TripleDES decAlg = TripleDES.Create();
        decAlg.Key = HashPassword(password);
        decAlg.IV = InitialisationVector;
        var decryptionStreamBacking = new MemoryStream();
        var decrypt = new CryptoStream(decryptionStreamBacking, decAlg.CreateDecryptor(), CryptoStreamMode.Write);
        decrypt.Write(bytes, 0, bytes.Length);
        decrypt.Flush();
        decrypt.Close();

        var decryptedData = new UTF8Encoding(false).GetString(decryptionStreamBacking.ToArray());
        ImportKey(decryptedData);
    }

    /// <summary>
    /// Hash the password with a Salt value matching the one used in BankAnywhereConfigEncryptor tool, to unlock the KeyStore.
    /// </summary>
    /// <param name="password">The plain Text password to be hashed.</param>
    /// <returns></returns>
    private static byte[] HashPassword(string password)
    {
        byte[] hashedPass = null;

        try
        {
            // Hash the password
            var passwordHasher = new Rfc2898DeriveBytes(password, Salt);
            hashedPass = passwordHasher.GetBytes(16);
            passwordHasher.Reset();

        }
        catch (Exception ex)
        {
           // _logger.LogError(ex, "HashPassword: Exception occurred hashing password text.");
        }
        return hashedPass;
    }
}




//public class Program
//{
//    public static void Main(string[] args)
//    {
//        IEncryptionProvider encryptionProvider = new AesEncryptionProvider();
//        IConfigEncryption encryptionService = new ConfigEncryption(encryptionProvider);

//        string plainText = "123456";
//        string encryptedText = encryptionService.EncryptConfig(plainText);
//        string decryptedText = encryptionService.DecryptConfig(encryptedText);

//        Console.WriteLine($"Plain Text: {plainText}");
//        Console.WriteLine($"Encrypted Text: {encryptedText}");
//        Console.WriteLine($"Decrypted Text: {decryptedText}");

//        Console.ReadLine();
//    }


//}


