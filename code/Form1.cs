using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

//https://dotblogs.com.tw/supershowwei/2015/12/23/160510
/*
在加密檔案的過程當中發生了長度錯誤的例外錯誤訊息，原來加密的 KeySize 大小會影響可加密的資料內容大小，可加密的資料內容大小估算公式為 (KeySize / 8) - 11。
如果想要改變 KeySize 大小，可以在宣告 RSACryptoServiceProvider 時就指定給它，例如：RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048); 就將 KeySize 大小指定為 2048。 
 */
using System.Security.Cryptography;
using System.IO;

//https://www.cnblogs.com/azeri/p/8973166.html
using OpenSSL.Core;
using OpenSSL.Crypto;

namespace CS_RSA_Formtest
{

    public partial class Form1 : Form
    {
        Tuple<string, string> m_RSA_key;
        public Form1()
        {
            InitializeComponent();
        }

        private Tuple<string, string> GenerateRSAKeys()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(4096);

            var publicKey = rsa.ToXmlString(false);
            var privateKey = rsa.ToXmlString(true);

            return Tuple.Create<string, string>(publicKey, privateKey);
        }

        private void RSAEncryptFile(string publicKey, string rawFilePath, string encryptedFilePath)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);

            using (FileStream testDataStream = File.OpenRead(rawFilePath))
            using (FileStream encrytpStream = File.OpenWrite(encryptedFilePath))
            {
                var testDataByteArray = new byte[testDataStream.Length];
                testDataStream.Read(testDataByteArray, 0, testDataByteArray.Length);

                var encryptDataByteArray = rsa.Encrypt(testDataByteArray, false);

                encrytpStream.Write(encryptDataByteArray, 0, encryptDataByteArray.Length);
            }
        }

        private void RSADecryptFile(string privateKey, string encryptedFilePath, string decryptedFilePath)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);

            using (FileStream encrytpStream = File.OpenRead(encryptedFilePath))
            using (FileStream decrytpStream = File.OpenWrite(decryptedFilePath))
            {
                var encryptDataByteArray = new byte[encrytpStream.Length];
                encrytpStream.Read(encryptDataByteArray, 0, encryptDataByteArray.Length);

                var decryptDataByteArray = rsa.Decrypt(encryptDataByteArray, false);

                decrytpStream.Write(decryptDataByteArray, 0, decryptDataByteArray.Length);
            }
        }

        private string RSAEncryptString(string publicKey, string content)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);

            var encryptString = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(content), false));

            return encryptString;
        }

        private string RSADecryptString(string privateKey, string encryptedContent)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);

            var decryptString = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(encryptedContent), false));

            return decryptString;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            m_RSA_key = GenerateRSAKeys();
            MessageBox.Show("publicKey: " + m_RSA_key.Item1 + "\nprivateKey: " + m_RSA_key.Item1);

        }

        private void button2_Click(object sender, EventArgs e)
        {
            String StrData = " It is RSA's Data";

            String encryptString01 = RSAEncryptString(m_RSA_key.Item1, StrData);
            String decryptString01 =RSADecryptString(m_RSA_key.Item2, encryptString01);

            String StrShow = String.Format("Sata: {0}\n\nencryptString01:{1}\n\ndecryptString01:{2}", StrData, encryptString01, decryptString01);

            MessageBox.Show(StrShow);
        }

        string privateKey = "", publicKey = "", text = "RSA-1024加解密。", ctext = "";
        /// <summary>
        /// 私钥解密
        /// </summary>
        public static string PrivateDecrypt(string privateKey, string text, Encoding encoding, int padding)
        {
            byte[] textBytes = Convert.FromBase64String(text);
            using (BIO bio = new BIO(privateKey))
            {
                using (OpenSSL.Crypto.RSA rsa = OpenSSL.Crypto.RSA.FromPrivateKey(bio))
                {
                    textBytes = rsa.PrivateDecrypt(textBytes, (OpenSSL.Crypto.RSA.Padding)padding);
                }
            }
            return encoding.GetString(textBytes);
        }

        /// <summary>
        /// 私钥加密
        /// </summary>
        public static string PrivateEncrypt(string privateKey, string text, Encoding encoding, int padding)
        {
            byte[] textBytes = encoding.GetBytes(text);
            using (BIO bio = new BIO(privateKey))
            {
                using (OpenSSL.Crypto.RSA rsa = OpenSSL.Crypto.RSA.FromPrivateKey(bio))
                {
                    textBytes = rsa.PrivateEncrypt(textBytes, (OpenSSL.Crypto.RSA.Padding)padding);
                }
            }
            return Convert.ToBase64String(textBytes);
        }

        /// <summary>
        /// 公钥解密
        /// </summary>
        public static string PublicDecrypt(string publicKey, string text, Encoding encoding, int padding)
        {
            byte[] textBytes = Convert.FromBase64String(text);
            using (BIO bio = new BIO(publicKey))
            {
                using (OpenSSL.Crypto.RSA rsa = OpenSSL.Crypto.RSA.FromPublicKey(bio))
                {
                    textBytes = rsa.PublicDecrypt(textBytes, (OpenSSL.Crypto.RSA.Padding)padding);
                }
            }
            return encoding.GetString(textBytes);
        }

        /// <summary>
        /// 公钥加密
        /// </summary>
        public static string PublicEncrypt(string publicKey, string text, Encoding encoding, int padding)
        {
            byte[] textBytes = encoding.GetBytes(text);
            using (BIO bio = new BIO(publicKey))
            {
                using (OpenSSL.Crypto.RSA rsa = OpenSSL.Crypto.RSA.FromPublicKey(bio))
                {
                    textBytes = rsa.PublicEncrypt(textBytes, (OpenSSL.Crypto.RSA.Padding)padding);
                    rsa.Dispose();
                }
                bio.Dispose();
            }
            return Convert.ToBase64String(textBytes);
        }

        /// <summary>
        /// 私钥签名
        /// </summary>
        public static string Sign(string privateKey, string text, Encoding encoding)
        {
            using (BIO bio = new BIO(privateKey))
            {
                using (CryptoKey cryptoKey = CryptoKey.FromPrivateKey(bio, null))
                {
                    using (MessageDigestContext sha256 = new MessageDigestContext(MessageDigest.SHA256))
                    {
                        byte[] msgByte = encoding.GetBytes(text);
                        byte[] signByte = sha256.Sign(msgByte, cryptoKey);
                        return Convert.ToBase64String(signByte);
                    }
                }
            }
        }

        /// <summary>
        /// 公钥验签
        /// </summary>
        public static bool Verify(string publicKey, string text, string sign, Encoding encoding)
        {
            using (BIO bio = new BIO(publicKey))
            {
                using (CryptoKey cryptoKey = CryptoKey.FromPublicKey(bio, null))
                {
                    using (MessageDigestContext sha256 = new MessageDigestContext(MessageDigest.SHA256))
                    {
                        byte[] msgByte = encoding.GetBytes(text);
                        byte[] signByte = Convert.FromBase64String(sign);
                        return sha256.Verify(msgByte, signByte, cryptoKey);
                    }
                }
            }
        }
        private void button3_Click(object sender, EventArgs e)
        {
            Encoding encoding = Encoding.UTF8;
            using (OpenSSL.Crypto.RSA rsa = new OpenSSL.Crypto.RSA())
            {
                rsa.GenerateKeys(4096, BigNumber.One, null, null);
                privateKey = rsa.PrivateKeyAsPEM;
                publicKey = rsa.PublicKeyAsPEM;
                MessageBox.Show("publicKey: " + publicKey + "\nprivateKey: " + privateKey);
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            Encoding encoding = Encoding.UTF8;
            int padding = 1;
            String StrShow = "";
            ctext = PrivateEncrypt(privateKey, text, encoding, padding);
            text = PublicDecrypt(publicKey, ctext, encoding, padding);
            StrShow = String.Format("PrivateEncrypt: {0}\nPublicDecrypt: {1}", ctext, text);

            ctext = PublicEncrypt(publicKey, text, encoding, padding);
            text = PrivateDecrypt(privateKey, ctext, encoding, padding);
            StrShow += "\n\n"+String.Format("PublicEncrypt: {0}\nPrivateDecrypt: {1}", ctext, text);

            var signText = Sign(privateKey, text, encoding);
            var signTag = Verify(publicKey, text, signText, encoding);
            StrShow += "\n\n" + String.Format("signText: {0}\nsignTag: {1}", signText, signTag);

            MessageBox.Show(StrShow);
        }
    }
}
