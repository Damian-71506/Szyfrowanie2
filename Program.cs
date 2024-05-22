using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Szyfrowanie_1
{
    public class Benchmark
    {
        private const int DataSize = 10 * 1024 * 1024; // 10 MB
        private static byte[] testData;
        private static byte[] encryptedData;

        public static void Main()
        {
            GenerateTestData();

            Console.WriteLine("Algorithm\tsekund/blok\tbajtów/sekundę(RAM)\tbajtów/sekundę(HDD)");
            TestAlgorithm<AesCryptoServiceProvider>("AES(CSP) 128-bit", 128);
            TestAlgorithm<AesCryptoServiceProvider>("AES(CSP) 256-bit", 256);
            TestAlgorithm<AesManaged>("AES Managed 128-bit", 128);
            TestAlgorithm<AesManaged>("AES Managed 256-bit", 256);
            TestAlgorithm<RijndaelManaged>("Rijndael Managed 128-bit", 128);
            TestAlgorithm<RijndaelManaged>("Rijndael Managed 256-bit", 256);
            TestAlgorithm<DESCryptoServiceProvider>("DES 56-bit", 56, false);
            TestAlgorithm<TripleDESCryptoServiceProvider>("3DES 168-bit", 168, false);
        }

        private static void GenerateTestData()
        {
            testData = new byte[DataSize];
            Random rnd = new Random();
            rnd.NextBytes(testData);
        }

        private static void TestAlgorithm<T>(string algorithmName, int keySize, bool setKeySize = true) where T : SymmetricAlgorithm, new()
        {
            byte[] key, iv;

            using (T algorithm = new T())
            {
                if (setKeySize)
                {
                    algorithm.KeySize = keySize;
                }
                algorithm.GenerateKey();
                algorithm.GenerateIV();
                key = algorithm.Key;
                iv = algorithm.IV;
            }

            double encryptMemoryTime = MeasureEncryptionTime<T>(key, iv, false);
            double decryptMemoryTime = MeasureDecryptionTime<T>(key, iv, false);
            double encryptDiskTime = MeasureEncryptionTime<T>(key, iv, true);
            double decryptDiskTime = MeasureDecryptionTime<T>(key, iv, true);

            double secondsPerBlock = (encryptMemoryTime + decryptMemoryTime) / 2;
            double bytesPerSecondRAM = DataSize / secondsPerBlock;
            double bytesPerSecondHDD = DataSize / ((encryptDiskTime + decryptDiskTime) / 2);

            Console.WriteLine($"{algorithmName}\t{secondsPerBlock:F6}\t{bytesPerSecondRAM:F6}\t{bytesPerSecondHDD:F6}");
        }

        private static double MeasureEncryptionTime<T>(byte[] key, byte[] iv, bool useDisk) where T : SymmetricAlgorithm, new()
        {
            byte[] dataToEncrypt = useDisk ? ReadDataFromDisk() : testData;
            Stopwatch stopwatch = new Stopwatch();

            using (T algorithm = new T())
            {
                algorithm.Key = key;
                algorithm.IV = iv;
                ICryptoTransform encryptor = algorithm.CreateEncryptor();

                stopwatch.Start();
                encryptedData = encryptor.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
                stopwatch.Stop();
            }

            return stopwatch.Elapsed.TotalSeconds;
        }

        private static double MeasureDecryptionTime<T>(byte[] key, byte[] iv, bool useDisk) where T : SymmetricAlgorithm, new()
        {
            byte[] dataToDecrypt = encryptedData;
            Stopwatch stopwatch = new Stopwatch();

            using (T algorithm = new T())
            {
                algorithm.Key = key;
                algorithm.IV = iv;
                ICryptoTransform decryptor = algorithm.CreateDecryptor();

                stopwatch.Start();
                decryptor.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
                stopwatch.Stop();
            }

            return stopwatch.Elapsed.TotalSeconds;
        }

        private static byte[] ReadDataFromDisk()
        {
            string filePath = "testdata.bin";
            if (!File.Exists(filePath))
            {
                File.WriteAllBytes(filePath, testData);
            }

            return File.ReadAllBytes(filePath);
        }
    }
}
