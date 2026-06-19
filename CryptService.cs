using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ComunicatiiSecurizate
{
    public class CryptService
    {
        public byte[] DerivedKey(int SharedKey)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] keyBytes = BitConverter.GetBytes(SharedKey);
            return sha256.ComputeHash(keyBytes);
        }
        public (byte[] Ciphertext, byte[] IV) Encrypt(string plainText, byte[] key)
        {
            Aes aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            byte[] iv = aes.IV;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    } 
                }
                return (ms.ToArray(), iv); 
            }
        }

        public string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }

        public  byte[] ComputeHash(byte[] data)
        {
            SHA256 sha256 = SHA256.Create();
            return sha256.ComputeHash(data);
        }
    }
}
