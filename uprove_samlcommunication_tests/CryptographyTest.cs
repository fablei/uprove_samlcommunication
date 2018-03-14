using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using uprove_samlcommunication;

namespace uprove_samlcommunication_tests
{
    [TestClass]
    public class CryptographyTest
    {
        private string KeystorePath = AppDomain.CurrentDomain.BaseDirectory + "\\CryptographyXMLs\\hybridissuer.pfx";
        private string KeystorePassword = "HybridIssuer";
        private string FriendlyName = "hybridissuer";

        private string SignedXML = "SAMLResponseParameterSimpleSamlPHP.txt";
        private string SignedXMLManipulated = "SAMLResponseParameterSimpleSamlPHPManipulated.txt";
        private string CertificateStringXML = "PublicCertificateSimpleSamlPHP.txt";
        
        [TestMethod]
        public void DecryptRSAOAEPMGF1P()
        {
            Cryptography crypto = new Cryptography();
            SamlCertificateController certController = new SamlCertificateController();
            X509Certificate2 cert = certController.GetCertificate("sp.example.ch", AppDomain.CurrentDomain.BaseDirectory + "\\Keys\\sp.jks", "localhost");
            string toDecrypt = "UV2SjA6ffHdVdywDl5EW6D9+ZhjPU8rxPnCqkPA8yjrKfkgHv3xKFTxtB0wRTnbQl8B8QFrvywvvh8JPR9iaTGkx+8C4tYyNiggkAHWLo8WeToHzoRTz2dJ01NRDNtS93cPue92zyJKcI0fIOe2lk4C3cyWQuLWFyuv1dKh3BoXcHTfl0fmOxBJEGRweYm1Sdp3sAh+9b6axjqaiGOWBnLavh7/z6OjTEbzpPb0VTz/CACj4QImQ1TWxfUJOJ1fuviF/TrsLt/q77pruEh0mjrC2zcUFBvHX1uXcNI7B2+n/TdVvHzXJxOnxCe/lXWgpssivFlK2DK87xMzoDixnQg==";
            string tokenEncryptedData = "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";

            crypto.Decrypt(toDecrypt, tokenEncryptedData, Cryptography.EncryptionAlgorithm.RSAOAEPMGF1P, cert);
        }

        [TestMethod]
        public void HashSuccessfulTest()
        {
            Cryptography crypto = new Cryptography();
            string toHash = "this should be hashed";

            string hashedValue1 = Convert.ToBase64String(crypto.Hash(toHash, Cryptography.HashTypes.SHA1));
            string hashedValue2 = Convert.ToBase64String(crypto.Hash(toHash, Cryptography.HashTypes.SHA1));

            Assert.AreEqual(hashedValue1, hashedValue2);
        }

        [TestMethod]
        public void HashFailedTest()
        {
            Cryptography crypto = new Cryptography();
            string toHash1 = "this should be hashed";
            string toHash2 = "this should be hashed!";

            string hashedValue1 = Convert.ToBase64String(crypto.Hash(toHash1, Cryptography.HashTypes.SHA1));
            string hashedValue2 = Convert.ToBase64String(crypto.Hash(toHash2, Cryptography.HashTypes.SHA1));

            Assert.AreNotEqual(hashedValue1, hashedValue2);
        }

        [TestMethod]
        public void StringSignatureVerificationSuccessfulTest()
        {
            SamlCertificateController certController = new SamlCertificateController();
            Cryptography crypto = new Cryptography();
            string toSign = "this should be signed";
            X509Certificate2 cert = certController.GetCertificate(FriendlyName, KeystorePath, KeystorePassword);
            Cryptography.SigningAlgorithm signingAlgo = Cryptography.SigningAlgorithm.SHA1withRSA;
            Cryptography.HashTypes hashingAlgo = Cryptography.HashTypes.SHA1;
            X509Certificate2 certValidate = new X509Certificate2(Encoding.UTF8.GetBytes(ReadFile("PublicCertificateHybridIssuer.txt")));

            try
            {
                // signing
                string signature = crypto.SignString(toSign, cert, signingAlgo, hashingAlgo);

                // verifying
                Assert.IsTrue(crypto.VerifySignedString(toSign, signature, certValidate, signingAlgo, hashingAlgo));    // import only the certificate as string
                Assert.IsTrue(crypto.VerifySignedString(toSign, signature, cert, signingAlgo, hashingAlgo));            // use the public key from the keystore
            }
            catch (SamlCommunicationException e) { Assert.Fail(e.Message); }
            catch (Exception e) { Assert.Fail(e.Message); }
        }

        [TestMethod]
        public void StringSignatureVerificationNotValidTest()
        {
            SamlCertificateController certController = new SamlCertificateController();
            Cryptography crypto = new Cryptography();
            string toSign1 = "this should be signed";
            string toSign2 = "this should be signed!";
            X509Certificate2 cert = certController.GetCertificate(FriendlyName, KeystorePath, KeystorePassword);
            Cryptography.SigningAlgorithm signingAlgo = Cryptography.SigningAlgorithm.SHA1withRSA;
            Cryptography.HashTypes hashingAlgo = Cryptography.HashTypes.SHA1;
            X509Certificate2 certValidate = new X509Certificate2(Encoding.UTF8.GetBytes(ReadFile("PublicCertificateHybridIssuer.txt")));

            try
            {
                // signing
                string signature = crypto.SignString(toSign1, cert, signingAlgo, hashingAlgo);

                // verifying
                Assert.IsFalse(crypto.VerifySignedString(toSign2, signature, certValidate, signingAlgo, hashingAlgo));    // import only the certificate as string
                Assert.IsFalse(crypto.VerifySignedString(toSign2, signature, cert, signingAlgo, hashingAlgo));            // use the public key from the keystore
            }
            catch (SamlCommunicationException e) { Assert.Fail(e.Message); }
            catch (Exception e) { Assert.Fail(e.Message); }
        }

        [TestMethod]
        public void XMLSignatureVerificationSuccessfulTest()
        {
            SamlCertificateController certController = new SamlCertificateController();
            Cryptography crypto = new Cryptography();

            try
            {
                Assert.IsTrue(crypto.VerifySignedXML(Encoding.UTF8.GetString(Convert.FromBase64String(ReadFile(SignedXML))), ReadFile(CertificateStringXML)));
            }
            catch (SamlCommunicationException e) { Assert.Fail(e.Message); }
            catch (Exception e) { Assert.Fail(e.Message); }
        }

        [TestMethod]
        public void XMLSignatureVerificationInvalidTest()
        {
            SamlCertificateController certController = new SamlCertificateController();
            Cryptography crypto = new Cryptography();

            try
            {
                Assert.IsFalse(crypto.VerifySignedXML(Encoding.UTF8.GetString(Convert.FromBase64String(ReadFile(SignedXMLManipulated))), ReadFile(CertificateStringXML)));
            }
            catch (SamlCommunicationException e) { Assert.Fail(e.Message); }
            catch (Exception e) { Assert.Fail(e.Message); }
        }





        private string ReadFile(string filename, bool trim = false)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\CryptographyXMLs\\" + filename;
            string[] files = File.ReadAllLines(path);
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < files.Length; i++)
            {
                if (trim)
                    sb.Append(files[i].ToString());
                else
                    sb.Append(files[i].ToString().Trim() + " ");
            }


            return sb.ToString();
        }

    }
}
