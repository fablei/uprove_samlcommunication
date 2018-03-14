using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using uprove_samlcommunication;
using uprove_samlcommunication.samlserialization;

namespace uprove_samlcommunication_tests
{
    [TestClass]
    public class SamlValidatorTest
    {
        private string xmlResponseFilename = "SamlResponseSimpleSamlPHP.xml";
        private string responseFilename = "SAMLResponseParameterSimpleSamlPHP.txt";
        private string xmlMetadataFile = "metadata-simpleidp.xml";
        private string xmlAuthnRequestFile = "AuthnRequestSimpleSamlPHP.xml";

        [TestMethod]
        public void CheckTimeValidTest()
        {
            Saml2Serializer serializer = new Saml2Serializer();
            SamlValidator validator = new SamlValidator();

            Response response = serializer.ConvertXMLToResponseObject(ReadFile(xmlResponseFilename));

            TimeZone localZone = TimeZone.CurrentTimeZone;
            DateTime actualTime = localZone.ToUniversalTime(DateTime.Now);

            try
            {
                // add a correct time to the response
                response.Assertion.Conditions.NotBefore = actualTime.AddSeconds(-20);
                response.Assertion.Conditions.NotOnOrAfter = actualTime.AddMinutes(5);
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = actualTime.AddMinutes(5);
                response.IssueInstant = actualTime.AddSeconds(-20);
                response.Assertion.IssueInstant = actualTime.AddSeconds(-20);

                Assert.IsTrue(validator.CheckTime(response));
            }
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }
        }

        [TestMethod]
        public void CheckTimeInvalidTest()
        {
            Saml2Serializer serializer = new Saml2Serializer();
            SamlValidator validator = new SamlValidator();

            Response response = serializer.ConvertXMLToResponseObject(ReadFile(xmlResponseFilename));

            TimeZone localZone = TimeZone.CurrentTimeZone;
            DateTime actualTime = localZone.ToUniversalTime(DateTime.Now);

            // response.Assertion.Conditions.NotBefore is wrong
            try
            {
                response.Assertion.Conditions.NotBefore = actualTime.AddSeconds(20);
                response.Assertion.Conditions.NotOnOrAfter = actualTime.AddMinutes(5);
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = actualTime.AddMinutes(5);
                response.IssueInstant = actualTime.AddSeconds(-20);
                response.Assertion.IssueInstant = actualTime.AddSeconds(-20);
                Assert.IsFalse(validator.CheckTime(response));
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // response.Assertion.Conditions.NotOnOrAfter is wrong
            try
            {
                response.Assertion.Conditions.NotBefore = actualTime.AddSeconds(-20);
                response.Assertion.Conditions.NotOnOrAfter = actualTime.AddMinutes(-20);
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = actualTime.AddMinutes(5);
                response.IssueInstant = actualTime.AddSeconds(-20);
                response.Assertion.IssueInstant = actualTime.AddSeconds(-20);

                Assert.IsFalse(validator.CheckTime(response));
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter is wrong
            try
            {
                response.Assertion.Conditions.NotBefore = actualTime.AddSeconds(-20);
                response.Assertion.Conditions.NotOnOrAfter = actualTime.AddMinutes(5);
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = actualTime.AddMinutes(-20);
                response.IssueInstant = actualTime.AddSeconds(-20);
                response.Assertion.IssueInstant = actualTime.AddSeconds(-20);

                Assert.IsFalse(validator.CheckTime(response));
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // response.IssueInstant is wrong
            try
            {
                response.Assertion.Conditions.NotBefore = actualTime.AddSeconds(-20);
                response.Assertion.Conditions.NotOnOrAfter = actualTime.AddMinutes(5);
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = actualTime.AddMinutes(5);
                response.IssueInstant = actualTime.AddSeconds(20);
                response.Assertion.IssueInstant = actualTime.AddSeconds(-20);

                Assert.IsFalse(validator.CheckTime(response));
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // response.Assertion.IssueInstant is wrong
            try
            {
                response.Assertion.Conditions.NotBefore = actualTime.AddSeconds(-20);
                response.Assertion.Conditions.NotOnOrAfter = actualTime.AddMinutes(5);
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = actualTime.AddMinutes(5);
                response.IssueInstant = actualTime.AddSeconds(-20);
                response.Assertion.IssueInstant = actualTime.AddSeconds(20);

                Assert.IsFalse(validator.CheckTime(response));
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected
        }

        [TestMethod]
        public void ValidateResponseWithoutTimeValidTest()
        {
            Saml2Serializer serializer = new Saml2Serializer();
            SamlValidator validator = new SamlValidator();
            string xml = Encoding.UTF8.GetString(Convert.FromBase64String(ReadFile(responseFilename)));
            EntityDescriptor entityDescriptor = serializer.ConvertXMLToEntityDescriptorObject(ReadFile(xmlMetadataFile));
            AuthnRequest authnRequest = serializer.ConvertXMLToAuthnRequestObject(ReadFile(xmlAuthnRequestFile));

            Response response = serializer.ConvertXMLToResponseObject(xml);

            bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);

            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public void ValidateResponseWithoutTimeInvalidTest()
        {
            Saml2Serializer serializer = new Saml2Serializer();
            SamlValidator validator = new SamlValidator();
            string xml = ReadFile(xmlResponseFilename);
            EntityDescriptor entityDescriptor = serializer.ConvertXMLToEntityDescriptorObject(ReadFile(xmlMetadataFile));
            AuthnRequest authnRequest = serializer.ConvertXMLToAuthnRequestObject(ReadFile(xmlAuthnRequestFile));

            Response response = serializer.ConvertXMLToResponseObject(xml);

            // wrong response.Status.StatusCode.Value
            try
            {
                response.Status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Requester";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // wrong response.Issuer
            try
            {
                response.Issuer = "wrongIssuer";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // wrong x509 certificate
            try
            {
                response.Signature.KeyInfo.X509Data.X509Certificate = response.Signature.KeyInfo.X509Data.X509Certificate + "s";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // response was changed / attack
            try
            {
                string attackedXML = ReadFile("ChangedSamlResponseSimpleSamlPHP.xml");

                response.Signature.KeyInfo.X509Data.X509Certificate = response.Signature.KeyInfo.X509Data.X509Certificate + "s";
                bool isValid = validator.ValidateResponse(response, attackedXML, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // wrong response.Destination
            try
            {
                response.Destination = "newdesinationaddress.com";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // wrong response.Assertion.Conditions.AudienceRestriction.Audience -> issuer
            try
            {
                response.Assertion.Conditions.AudienceRestriction.Audience = "otherIssuer";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // wrong response.InResponseTo
            try
            {
                response.InResponseTo = "InResponseTo";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected

            // wrong response.Assertion.Subject.SubjectConfirmation.Method
            try
            {
                response.Assertion.Subject.SubjectConfirmation.Method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
                bool isValid = validator.ValidateResponse(response, xml, entityDescriptor, authnRequest, false);
            }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }   // exception expected in this test
            catch (Exception e) { Assert.Fail(e.Message); }     // not this kind of exception expected
        }

        private string ReadFile(string filename, bool trim = false)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\ValidatorXMLs\\" + filename;
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
