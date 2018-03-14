using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace uprove_samlcommunication
{
    public class Cryptography
    {
        #region AlgorithmEnums
        public enum HashTypes { SHA1, SHA256 }
        public enum SigningAlgorithm { SHA1withRSA, SHA256withRSA }
        public enum EncryptionAlgorithm { AES256CBC, RSAOAEPMGF1P }
        #endregion AlgorithmEnums

        #region Decrypt
        /// <summary>
        /// decrypts data with a given certificate
        /// </summary>
        /// <param name="tokenDecryptionKey">decryption key from the token</param>
        /// <param name="tokenDataToDecrypt">data to decrypt</param>
        /// <param name="encAlg">used algorithm</param>
        /// <param name="cert">certificate needed for decryption</param>
        /// <returns>encrypted data or an exception is thrown</returns>
        public string Decrypt(string tokenDecryptionKey, string tokenDataToDecrypt, EncryptionAlgorithm encAlg, X509Certificate2 cert)
        {
            // https://msdn.microsoft.com/en-us/library/system.security.cryptography.rsacryptoserviceprovider(v=vs.110).aspx
            // https://msdn.microsoft.com/en-us/library/aa967562(v=vs.90).aspx

            byte[] plainText = new byte[] { };
            LogService.Log(LogService.LogType.Info, "Cryptography - Decrypt called");

            if (encAlg == EncryptionAlgorithm.AES256CBC)
            {
                try
                {
                    byte[] tokenData = Convert.FromBase64String(tokenDataToDecrypt);

                    int algoHash = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".GetHashCode();


                    using (Aes aes = new AesManaged())
                    {
                        aes.Key = (cert.PrivateKey as RSACryptoServiceProvider).Decrypt(Convert.FromBase64String(tokenDecryptionKey), true);
                        int ivSize = aes.BlockSize / 8;
                        byte[] iv = new byte[ivSize];
                        Buffer.BlockCopy(tokenData, 0, iv, 0, iv.Length);
                        aes.Padding = PaddingMode.None;
                        aes.Mode = CipherMode.CBC;

                        // decrypt the encrypted text
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(tokenData, 0, tokenData.Length);
                            }

                            plainText = ms.ToArray();
                        }
                    }
                    //SymmetricAlgorithm alg = new AesManaged();
                    //alg.Key = (cert.PrivateKey as RSACryptoServiceProvider).Decrypt(Convert.FromBase64String(tokenDecryptionKey), true);
                    //int ivSize = alg.BlockSize / 8;
                    //byte[] iv = new byte[ivSize];
                    //Buffer.BlockCopy(tokenData, 0, iv, 0, iv.Length);
                    //alg.Padding = PaddingMode.None;
                    //alg.Mode = CipherMode.CBC;
                    //ICryptoTransform decrTransform = alg.CreateDecryptor(alg.Key, iv);
                    //plainText = decrTransform.TransformFinalBlock(tokenData, iv.Length, tokenData.Length - iv.Length);
                    //decrTransform.Dispose();
                }
                catch (Exception e)
                {
                    throw new SamlCommunicationException("Error while decrypting.", e, SamlCommunicationType.SAMLVERIFICATION);
                }
            }

            LogService.Log(LogService.LogType.Info, "successfully decrypted the given value");
            return Encoding.UTF8.GetString(plainText);
        }
        #endregion Decrypt

        #region Hash
        /// <summary>
        /// Hashes the given string with the chosen hash algorithm
        /// </summary>
        /// <param name="toHash">string to hash</param>
        /// <param name="hashType">hash algorithm with which the string must be hashed</param>
        /// <returns>a hashed array or an empty byte array</returns>
        public byte[] Hash(string toHash, HashTypes hashType = HashTypes.SHA1)
        {
            LogService.Log(LogService.LogType.Info, "Cryptography - Hash called");
            byte[] hash;
            if (hashType == HashTypes.SHA1)
            {
                SHA1Managed sha1 = new SHA1Managed();
                hash = sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(toHash));
            }
            else if (hashType == HashTypes.SHA256)
            {
                SHA256Managed sha256 = new SHA256Managed();
                hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(toHash));
            }
            else
                hash = new byte[] { };

            LogService.Log(LogService.LogType.Info, "successfully hashed the given value");
            return hash;
        }
        #endregion Hash

        #region SignString
        /// <summary>
        /// Signs the given string with the given certificate (private key) and the given algorithm
        /// </summary>
        /// <param name="toSign">string to sign</param>
        /// <param name="cert">certificate with private key, used for siging</param>
        /// <param name="signingAlgorithm">defined algorithm, which is used for siging</param>
        /// <param name="hashAlgorithm">defined algorithm, which is used for hashing</param>
        /// <returns>signed string or an exception is thrown</returns>
        public string SignString(string toSign, X509Certificate2 cert, SigningAlgorithm signingAlgorithm, HashTypes hashAlgorithm = HashTypes.SHA1)
        {
            LogService.Log(LogService.LogType.Info, "Cryptography - SignString called");
            try
            {
                if (cert == null)
                    throw new SamlCommunicationException("There is no certificate available", SamlCommunicationType.SAMLVERIFICATION);

                RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PrivateKey;
                csp.ToXmlString(false);

                byte[] signedData = csp.SignHash(Hash(toSign, hashAlgorithm), GetStringAlgorithmus(signingAlgorithm));
                LogService.Log(LogService.LogType.Info, "successfully signed '" + toSign + "'");
                return Convert.ToBase64String(signedData);
            }
            catch (Exception e)
            {
                throw new SamlCommunicationException("Error was thrown in cryptography", e, SamlCommunicationType.SAMLVERIFICATION);
            }
        }
        #endregion SignString

        #region VerifySignedString
        /// <summary>
        /// Verifies if the given signedString (string which was signed) and its result (signautre) are matching
        /// </summary>
        /// <param name="signedString">was the string which was signed</param>
        /// <param name="signature">result from the signing process</param>
        /// <param name="cert">certificate in which the public key for the validation is used</param>
        /// <param name="signedAlgorithm">with which algorithm the signature was made</param>
        /// <param name="hashAlgorithm">which algorithm was used for the hashing</param>
        /// <returns>true -> valid, false or exception -> invalid</returns>
        public bool VerifySignedString(string signedString, string signature, X509Certificate2 cert, SigningAlgorithm signedAlgorithm, HashTypes hashAlgorithm = HashTypes.SHA1)
        {
            LogService.Log(LogService.LogType.Info, "Cryptography - VerifySignedString called");
            try
            {
                if (cert == null)
                    throw new SamlCommunicationException("There is no certificate available", SamlCommunicationType.SAMLVERIFICATION);

                RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
                bool isValid = csp.VerifyHash(Hash(signedString, hashAlgorithm), GetStringAlgorithmus(signedAlgorithm), Convert.FromBase64String(signature));
                LogService.Log(LogService.LogType.Info, "signed string is " + (isValid ? "valid" : "invalid"));
                return isValid;
            }
            catch (Exception e)
            {
                throw new SamlCommunicationException("Error was thrown in cryptography", e, SamlCommunicationType.SAMLVERIFICATION);
            }
        }
        #endregion VerifySignedString

        #region VerifySignedXML
        /// <summary>
        /// Verifies the given xmls signature
        /// </summary>
        /// <param name="signedXMLString">xml to verify</param>
        /// <param name="x509Certificate">certificate which was used so sign the xml</param>
        /// <returns>true -> signature matches the signing, false -> signature does not matches the signature</returns>
        public bool VerifySignedXML(string signedXMLString, string x509Certificate)
        {
            LogService.Log(LogService.LogType.Info, "Cryptography - VerifySignedXML called");
            // https://msdn.microsoft.com/en-us/library/ms229950(v=vs.110).aspx
            try
            {
                // load certificate string into X509Certificate-Object
                X509Certificate2 cert = new X509Certificate2(System.Text.Encoding.UTF8.GetBytes(x509Certificate));
                RSACryptoServiceProvider rsaPublicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;

                // load xml
                XmlDocument xml = new XmlDocument();
                xml.PreserveWhitespace = true;
                xml.LoadXml(signedXMLString);

                // Create a new SignedXml object and pass it the XML document class.
                SignedXml signedXml = new SignedXml(xml);

                // Find the "Signature" node and create a new XmlNodeList object.
                XmlNodeList nodeList = xml.GetElementsByTagName("ds:Signature");

                // Load the signature node.
                signedXml.LoadXml((XmlElement)nodeList[0]);

                // Check the signature and return the result.
                bool isValid = signedXml.CheckSignature(rsaPublicKey);

                LogService.Log(LogService.LogType.Info, "signed xml is " + (isValid ? "valid" : "invalid"));
                return isValid;
            }
            catch (Exception e)
            {
                throw new SamlCommunicationException("Exception while verifying xml", e, SamlCommunicationType.SAMLVERIFICATION);
            }
        }
        #endregion VerifySignedXML

        #region GetStringAlgorithmus
        /// <summary>
        /// Returns the CryptoConfig.MapNameToOID(..) which matches with the given algorithm
        /// </summary>
        /// <param name="algo">SigningAlgorithm with which the signature should make / was made </param>
        /// <returns>string from the CryptoConfig.MapNameToOID(algo)</returns>
        private string GetStringAlgorithmus(SigningAlgorithm algo)
        {
            string algorithm = "SHA1withRSA";

            if (algo == SigningAlgorithm.SHA1withRSA)
                algorithm = "SHA1withRSA";
            else if (algo == SigningAlgorithm.SHA256withRSA)
                algorithm = "SHA256";

            return CryptoConfig.MapNameToOID(algorithm);
        }
        #endregion GetStringAlgorithmus
    }
}
