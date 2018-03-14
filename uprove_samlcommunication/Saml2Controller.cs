using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using uprove_samlcommunication.samlserialization;

namespace uprove_samlcommunication
{
    public class Saml2Controller
    {
        #region Properties
        private SamlArchiver archiver = new SamlArchiver();
        private Cryptography crypto = new Cryptography();
        private SamlCertificateController certController = new SamlCertificateController();
        private SamlMetadataController metadataController = new SamlMetadataController();
        private Saml2Serializer serializer = new Saml2Serializer();
        private SamlValidator verifier = new SamlValidator();

        private X509Certificate2 certificate;
        private bool initialized = false;
        private string metadataDirectoryPath;
        #endregion Properties

        #region Init
        /// <summary>
        /// Initializes the Saml2Controller
        /// </summary>
        /// <param name="keystorePath">path to the own keystore with the certificate (needed when signing an authn request)</param>
        /// <param name="keystorePassword">password for open the certificate</param>
        /// <param name="friendlyName">friendly name of the certificate</param>
        /// <param name="metadataDirectoryPath">metadata directory where the metadatas from the community parties were stored</param>
        public void Init(string keystorePath, string keystorePassword, string friendlyName, string metadataDirectoryPath)
        {
            LogService.Log(LogService.LogType.Info, "Saml2Controller - init, load certificate (" + keystorePath + " / " + friendlyName + ") and metadata (" + metadataDirectoryPath + ")");
            certificate = LoadCertificate(keystorePath, keystorePassword, friendlyName);
            this.metadataDirectoryPath = metadataDirectoryPath;
            initialized = true;
            LogService.Log(LogService.LogType.Info, "Saml2Controller - initialized");
        }
        #endregion Init

        #region CreateSamlAuthnRequest
        /// <summary>
        /// Creates a saml authentication request with the given authentication request properties
        /// </summary>
        /// <param name="assertionConsumerServiceURL"></param>
        /// <param name="attributeConsumingServiceIndex"></param>
        /// <param name="destination"></param>
        /// <param name="forceAuthn"></param>
        /// <param name="providerName"></param>
        /// <param name="issuer"></param>
        /// <param name="signAlgorithm"></param>
        /// <returns>signed saml request</returns>
        public string CreateSamlAuthnRequest(string assertionConsumerServiceURL, int attributeConsumingServiceIndex, string destination,
            bool forceAuthn, string providerName, string issuer, Cryptography.SigningAlgorithm signAlgorithm = Cryptography.SigningAlgorithm.SHA1withRSA)
        {
            LogService.Log(LogService.LogType.Info, "CreateSamlAuthnRequest called");
            if (!initialized)
                throw new SamlCommunicationException("Init must be called first", SamlCommunicationType.SAMLCOMMUNICATION);

            Saml2AuthnRequest authnRequest = new Saml2AuthnRequest()
            {
                AssertionConsumerServiceURL = assertionConsumerServiceURL,
                AttributeConsumingServiceIndex = attributeConsumingServiceIndex,
                Destination = destination,
                ForceAuthn = forceAuthn,
                ProviderName = providerName,
                Issuer = issuer
            };

            LogService.Log(LogService.LogType.Info, "CreateSamlAuthnRequest authnRequest properties set - '" + authnRequest.ToString() + "'");

            return CreateSamlAuthnRequest(authnRequest, signAlgorithm);
        }
        #endregion CreateSamlAuthnRequest

        #region CreateSamlAuthnRequest
        /// <summary>
        /// Creates a saml authentication request
        /// </summary>
        /// <param name="authnRequest">contains the authentication request properties</param>
        /// <param name="signAlgorithm">algorithm to sign the saml request</param>
        /// <returns>signed saml request</returns>
        public string CreateSamlAuthnRequest(Saml2AuthnRequest authnRequest,
            Cryptography.SigningAlgorithm signAlgorithm = Cryptography.SigningAlgorithm.SHA1withRSA)
        {
            if (!initialized)
                throw new SamlCommunicationException("Init must be called first", SamlCommunicationType.SAMLCOMMUNICATION);

            // load signing certificate
            X509Certificate2 signingCertificate = certificate; // LoadCertificate();
            // set creation time
            TimeZone localZone = TimeZone.CurrentTimeZone;
            authnRequest.IssueInstant = localZone.ToUniversalTime(DateTime.Now);
            // make id -> hash the authn request make it unique
            byte[] hash = crypto.Hash(authnRequest.ToXML(), Cryptography.HashTypes.SHA256);
            authnRequest.ID = Convert.ToBase64String(hash);

            // set signing algorithm
            string signingAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            if (signAlgorithm == Cryptography.SigningAlgorithm.SHA256withRSA)
                signingAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; // TODO correct algorithm

            string original;
            string deflated = serializer.Deflate(authnRequest.ToXML(), out original);

            // todo store authn request in storage!
            archiver.SetObjectToArchive(authnRequest.ID, Convert.ToBase64String(Encoding.UTF8.GetBytes(authnRequest.ToXML())));

            // SAMLResponse=value&RelayState=value&SigAlg=value
            string toSign = "SAMLRequest=" + WebUtility.UrlEncode(deflated)         // HttpUtility if in Webproject
                                        + "&RelayState=" + WebUtility.UrlEncode(authnRequest.ID)
                                        + "&SigAlg=" + WebUtility.UrlEncode(signingAlgorithm);

            string signature = crypto.SignString(toSign, signingCertificate, signAlgorithm);
            string request = authnRequest.Destination + "?" + toSign + "&Signature=" + WebUtility.UrlEncode(signature);

            LogService.Log(LogService.LogType.Info, "CreateSamlAuthnRequest - authnRequest created: '" + request + "'");

            return request;
        }
        #endregion CreateSamlAuthnRequest

        #region ReadResponse
        /// <summary>
        /// Reads the given saml response and extracts the attributes
        /// </summary>
        /// <param name="samlResponse">saml response with or without encrypted assertion</param>
        /// <param name="relaystate">related state to saml response</param>
        /// <param name="responseAssertionAttributes">contains the extracted attributes from the assertion (if there were any)</param>
        /// <returns>true -> valid response -> else exception is thrown</returns>
        public bool ReadResponse(string samlResponse, string relaystate, out Dictionary<string, ResponseAssertionAttribute> responseAssertionAttributes)
        {
            if (!initialized)
                throw new SamlCommunicationException("Init must be called first", SamlCommunicationType.SAMLCOMMUNICATION);

            LogService.Log(LogService.LogType.Info, "ReadResponse called");
            responseAssertionAttributes = new Dictionary<string, ResponseAssertionAttribute>();

            try
            {
                LogService.Log(LogService.LogType.Info, "ReadResponse response: '" + samlResponse + "'; relatedstate: '" + relaystate + "'");
                // decode SAMLResponse first (base64)
                string responseXML = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponse));

                // get response as object
                Response response = serializer.ConvertXMLToResponseObject(responseXML);

                // remove encrypted assertion if there is one
                if (response.EncryptedAssertion != null)
                    RemoveEncryptedAssertion(response); // TODO should check first if response is valid or not (saving computation power)
                
                // load metadata from issuer
                EntityDescriptor metadata = LoadMetadataFile(response.Issuer, metadataDirectoryPath);

                // load AuthnRequest from archiver
                string authnRequestString = archiver.GetArchivedObject(response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo);
                AuthnRequest authnRequest = serializer.ConvertXMLToAuthnRequestObject(Encoding.UTF8.GetString(Convert.FromBase64String(authnRequestString)));

                // check if response is valid
                if (verifier.ValidateResponse(response, responseXML, metadata, authnRequest))
                {
                    LogService.Log(LogService.LogType.Info, "ReadResponse extract attributes from response");
                    responseAssertionAttributes = serializer.GetAttributes(response);
                    return true;
                }

                throw new SamlCommunicationException("Response is not valid.");
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "ReadResponse failed", e);
                throw new SamlCommunicationException("ReadResponse failed", e, SamlCommunicationType.SAMLCOMMUNICATION);
            }
        }
        #endregion ReadResponse

        #region LoadCertificate
        /// <summary>
        /// Loads the certificate with the defined settings in the app.config
        /// </summary>
        /// <returns>certificate or an exception</returns>
        private X509Certificate2 LoadCertificate(string keystorePath, string keystorePassword, string friendlyName)
        {
            // create signing certificate for issuer
            //string keystorePath = ConfigurationManager.AppSettings.Get("KeystoreDirectoryPath") + ConfigurationManager.AppSettings.Get("KeystoreName");
            //string keystorePassword = ConfigurationManager.AppSettings.Get("KeystorePassword");
            //string friendlyName = ConfigurationManager.AppSettings.Get("KeystoreFriendlyName");
            X509Certificate2 cert = certController.GetCertificate(friendlyName, keystorePath, keystorePassword);
            if (cert == null)
                throw new SamlCommunicationException("Certificate is null, no certificate found", SamlCommunicationType.SAMLCOMMUNICATION);

            return cert;
        }
        #endregion LoadCertificate

        #region LoadMetadataFile
        /// <summary>
        /// Loads the xml metadata file from the defined MetadataFilePath in the MetadataController
        /// </summary>
        /// <param name="issuerName">the name of the file</param>
        /// <param name="metadataDirectory">directory where the metadata files where stored</param>
        /// <returns>Converts the metadata file content to an EntityDescriptor (which the file is) or an exception</returns>
        private EntityDescriptor LoadMetadataFile(string issuerName, string metadataDirectory)
        {
            try
            {
                //string metadataDirectoryPath = ConfigurationManager.AppSettings.Get("MetadataDirectoryPath");
                string xml = metadataController.ReadFile(issuerName, metadataDirectory, true);

                if (xml == "")
                    throw new SamlCommunicationException("metadata-" + issuerName + ".xml is empty", SamlCommunicationType.SAMLCOMMUNICATION);

                return serializer.ConvertXMLToEntityDescriptorObject(xml);
            }
            catch (Exception e)
            {
                throw new SamlCommunicationException("Could not read metadata file.", e, SamlCommunicationType.SAMLCOMMUNICATION);
            }
        }
        #endregion LoadMetadataFile

        #region RemoveEncryptedAssertion
        /// <summary>
        /// Removes the encryption from a given encrypted assertion
        /// </summary>
        /// <param name="responseWithEncAssertion">encrypted assertion to encrypt</param>
        public void RemoveEncryptedAssertion(Response responseWithEncAssertion)
        {
            EncryptedData encData = responseWithEncAssertion.EncryptedAssertion.EncryptedData;
            LogService.Log(LogService.LogType.Info, "RemoveEncryptedAssertion called");

            // maybe there is an reference available - if so, check reference id
            if (encData.KeyInfo.RetrievalMethod != null)
            {
                string id = encData.KeyInfo.RetrievalMethod.URI;

                // the # is needed because there is a reference in the id
                if (("#" + responseWithEncAssertion.EncryptedAssertion.EncryptedKey.Id) == id)
                {
                    EncryptedKey encKey = responseWithEncAssertion.EncryptedAssertion.EncryptedKey;
                    string alg = encKey.EncryptionMethod.Algorithm;

                    string decryptionKey = encKey.CipherData.CipherValue;
                    string encryptedData = encData.CipherData.CipherValue;

                    string decryptedAssertion = crypto.Decrypt(decryptionKey, encryptedData, Cryptography.EncryptionAlgorithm.AES256CBC, certificate); // LoadCertificate());

                    // get only <saml2:Assertion ..> ... </saml2:Assertion> from the decrypted string (remove junk) 
                    string assertion = Regex.Match(decryptedAssertion, "(<saml2:Assertion)(.|\\s)*(<\\/saml2:Assertion>)").Groups[0].Value;

                    responseWithEncAssertion.Assertion = serializer.ConvertXMLToAssertionObject(assertion);
                    LogService.Log(LogService.LogType.Info, "RemoveEncryptedAssertion encrypted assertion is decrypted");
                }
                else
                    throw new SamlCommunicationException("EncryptedData.KeyInfo.RetrievalMethod.URI does not match reference EncryptedKey.Id",
                        SamlCommunicationType.SAMLCOMMUNICATION);
            }
            else
                throw new SamlCommunicationException(
                    "EncryptedAssertion must have a EncryptedData.KeyInfo.RetrievalMethod.URI - your version is not supported at the moment.",
                    SamlCommunicationType.SAMLCOMMUNICATION);
        }
        #endregion RemoveEncryptedAssertion
    }
}
