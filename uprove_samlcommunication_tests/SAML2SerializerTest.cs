using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using uprove_samlcommunication;
using uprove_samlcommunication.samlserialization;

namespace uprove_samlcommunication_tests
{
    [TestClass]
    public class SAML2SerializerTest
    {
        //private string xmlFilename = "AuthnRequestSimpleSamlPHP.xml";
        private string xmlFilename = "AuthnRequestSTIAMHub.xml";
        //private string xmlFilename = "AuthnRequestOnelogin.xml";

        private string xmlResponseFilename = "SamlResponseSimpleSamlPHP.xml";

        [TestMethod]
        public void GetAttributesTest()
        {
            string xml = ReadFile(xmlResponseFilename);
            Saml2Serializer saml = new Saml2Serializer();
            Dictionary<string, ResponseAssertionAttribute> dictionary = saml.GetAttributes(xml);

            Assert.AreEqual("Max", dictionary["surname"].Values[0]);
        }

        [TestMethod]
        public void CreateAuthnRequstTest()
        {
            string xmlString = ReadFile(xmlFilename);
            Saml2Serializer saml = new Saml2Serializer();
            Cryptography crypto = new Cryptography();
            Saml2AuthnRequest authn = new Saml2AuthnRequest();

            AuthnRequest authnRequest = saml.ConvertXMLToAuthnRequestObject(xmlString);

            authn.AssertionConsumerServiceURL = authnRequest.AssertionConsumerServiceURL;
            authn.AttributeConsumingServiceIndex = authnRequest.AttributeConsumingServiceIndex;
            authn.Destination = authnRequest.Destination;
            authn.ForceAuthn = authnRequest.ForceAuthn;
            authn.Issuer = authnRequest.Issuer;
            authn.ProviderName = "HybridIssuer";

            TimeZone localZone = TimeZone.CurrentTimeZone;

            authn.IssueInstant = localZone.ToUniversalTime(DateTime.Now);
            authn.ID = "65464-6546-6454889-3313";

            string original;
            string zipped = saml.Deflate(authn.ToXML(), out original);

            string sigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

            // SAMLResponse=value&RelayState=value&SigAlg=value
            string toSign = "SAMLRequest=" + HttpUtility.UrlEncode(zipped, Encoding.UTF8)
                                        + "&RelayState=" + HttpUtility.UrlEncode("34bad366-f60b-4491-a462-230ea22423ad", Encoding.UTF8)
                                        + "&SigAlg=" + HttpUtility.UrlEncode(sigAlg, Encoding.UTF8);

            //byte[] sig = saml.SignXML(xmlString);
            //string signature = Convert.ToBase64String(sig);

            string keystorePath = AppDomain.CurrentDomain.BaseDirectory + "\\Keys\\hybridissuer.pfx";
            string keystorePassword = "HybridIssuer";
            string friendlyName = "hybridissuer";
            SamlCertificateController certController = new SamlCertificateController();
            X509Certificate2 cert = certController.GetCertificate(friendlyName, keystorePath, keystorePassword);

            string signature = crypto.SignString(toSign, cert, Cryptography.SigningAlgorithm.SHA1withRSA);
            string request = authnRequest.Destination + "?" + toSign + "&Signature=" + HttpUtility.UrlEncode(signature, Encoding.UTF8);
        }

        [TestMethod]
        public void AuthnRequestObjectTest()
        {
            string xmlString = ReadFile(xmlFilename);

            Saml2Serializer saml = new Saml2Serializer();
            AuthnRequest authnRequest = saml.ConvertXMLToAuthnRequestObject(xmlString);

            Assert.AreEqual("https://stiamhub:8443/Hub/SAML/SSO/Browser", authnRequest.Destination);
            Assert.AreEqual("http://localhost:14545/", authnRequest.AssertionConsumerServiceURL);
            Assert.AreEqual("hybridissuer.ch", authnRequest.Issuer);
            //Assert.AreEqual("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", authnRequest.NameIDPolicy.Format);
        }

        [TestMethod]
        public void CheckAuthnRequestGenerationTest()
        {
            string xmlString = ReadFile(xmlFilename);

            Saml2Serializer saml = new Saml2Serializer();
            string original;
            string zipped = saml.Deflate(xmlString, out original);
            string unzipped = saml.Inflate(zipped);


            Assert.AreEqual(original, unzipped);

            // result: fZLLTsMwEEV/xfI+OCkONKOmUqBCrVRo1RQWbJCTOMQosYPHAfr3uClILFA3XszcOXcenqHo2kkP2eAavZPvg0RHMkRpnTL61mgcOmlzaT9UKR9365Q2zvXA2FsPEY95zChZ+BqlxbHglEaf9yHRNUMBU84v2XIoWJ7dr1meb9iNNZ/egJI7Y0s5Oqe0Fi1KSlaLlL5UCZ9Gk6QOoujqOuCFqALh34Anop6G0+uaR7GXIg5ypdEJ7VI6CaOrIAqDiO/DGPglhOFFksTPlGytcaY07Y3SldKvKR2sBiNQIWjRSQRXwrE3mFyEUJxECMv9fhtsN/mekidpcZzNCyj56lqNcFrbeVb/Y0zJnMzGAhh7tn8Z5xHi9xJ03hwKqyo1AmbsL+6X3sODB6wWW9Oq8kCytjWft1YKJ1Pq7CDHhXfCnbc8RlQV1KMU+uPs6KR2lDBvxP75L/Nv
        }

        private string ReadFile(string filename, bool trim = false)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\TestXMLs\\" + filename;
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
