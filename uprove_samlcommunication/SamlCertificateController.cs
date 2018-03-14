using System.Security.Cryptography.X509Certificates;

namespace uprove_samlcommunication
{
    public class SamlCertificateController
    {
        #region GetCertificate
        /// <summary>
        /// Gets a certificate from the given folder, opens the store (#pkcs7) and searches for the given certificate
        /// </summary>
        /// <param name="friendlyName">friendlyName of the searched certificate</param>
        /// <param name="keystorePath">path to the keystore, in which the searched certificate is</param>
        /// <param name="keystorePassword">password to open the certificate store</param>
        /// <returns>certificate -> if it is found in the keystore (#pkcs7), or an exception is thrown</returns>
        public X509Certificate2 GetCertificate(string friendlyName, string keystorePath, string keystorePassword)
        {
            LogService.Log(LogService.LogType.Info, "SamlCertificateController - GetCertificate called");
            X509Certificate2Collection certCollection = new X509Certificate2Collection();
            certCollection.Import(keystorePath, keystorePassword, X509KeyStorageFlags.Exportable);

            foreach (X509Certificate2 cert in certCollection)
            {
                if (cert.FriendlyName == friendlyName)
                {
                    return cert;
                }
            }

            LogService.Log(LogService.LogType.Info, "Could not get certificate from certificate store");
            throw new SamlCommunicationException("Could not get certificate from certificate store");
        }
        #endregion GetCertificate
    }
}
