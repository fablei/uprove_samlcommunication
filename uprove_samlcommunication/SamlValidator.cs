using System;
using uprove_samlcommunication.samlserialization;

namespace uprove_samlcommunication
{
    public class SamlValidator
    {
        #region Properties
        private Cryptography crypto = new Cryptography();
        #endregion Properties

        #region ValidateResponse
        /// <summary>
        /// Validates if the <br/>
        /// - status code <br/>
        /// - issuer <br/>
        /// - signature <br/>
        /// - [times] <br/>
        /// - destination <br/>
        /// - inResponseTo <br/>
        /// - SubjectConfirmation.Method <br/>
        /// are correct and matching with the right attributes
        /// </summary>
        /// <param name="response">The response string as object</param>
        /// <param name="responseXML">the response string as xml -> string</param>
        /// <param name="metadata">metadata from the sender (response issuer)</param>
        /// <param name="authnRequest">the sent authn request from this response</param>
        /// <param name="validateWithTime">true-> validate the time, false->do not validate time</param>
        /// <returns></returns>
        public bool ValidateResponse(Response response, string responseXML, EntityDescriptor metadata, AuthnRequest authnRequest, bool validateWithTime = true)
        {
            LogService.Log(LogService.LogType.Info, "SamlValidator - ValidateResponse called");
            // check status code first
            if (response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success")
                throw new SamlCommunicationException("StatusCode is not successful", SamlCommunicationType.SAMLVERIFICATION);
            // check InResponseTo
            if (response.InResponseTo != authnRequest.ID || (response.Assertion != null &&
                response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != authnRequest.ID))
                throw new SamlCommunicationException("InResponseTo does not match with the sent ID in authn request", SamlCommunicationType.SAMLVERIFICATION);
            // check if issuer is the same
            if (response.Issuer != metadata.entityID)
                throw new SamlCommunicationException("EntityId does not match with Issuer", SamlCommunicationType.SAMLVERIFICATION);
            // check certificates first
            if (!response.Signature.KeyInfo.X509Data.X509Certificate.Equals(metadata.IDPSSODescriptor.KeyDescriptor[0].KeyInfo.X509Data.X509Certificate))
                throw new SamlCommunicationException("Certificate does not match", SamlCommunicationType.SAMLVERIFICATION);
            // check signature
            string cert = "-----BEGIN CERTIFICATE-----" + metadata.IDPSSODescriptor.KeyDescriptor[0].KeyInfo.X509Data.X509Certificate.Trim() + "-----END CERTIFICATE-----";
            if (!crypto.VerifySignedXML(responseXML, cert))
                throw new SamlCommunicationException("Signature in the Response is not valid", SamlCommunicationType.SAMLVERIFICATION);
            // check time/date
            if (validateWithTime)
                CheckTime(response);
            // check destination
            if (response.Destination != authnRequest.AssertionConsumerServiceURL)
                throw new SamlCommunicationException("Destination does not match", SamlCommunicationType.SAMLVERIFICATION);
            // check audence restriction
            if (response.Assertion.Conditions.AudienceRestriction.Audience != authnRequest.Issuer)
                throw new SamlCommunicationException("AudenceRestriction is not the given issuer from the authn request", SamlCommunicationType.SAMLVERIFICATION);

            // check if bearer assertion
            if (response.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer")
                throw new SamlCommunicationException("Is no bearer assertion", SamlCommunicationType.SAMLVERIFICATION);

            LogService.Log(LogService.LogType.Info, "response validation was successfully");
            return true;
        }
        #endregion ValidateResponse

        #region CheckTime
        /// <summary>
        /// Checks the relevante times in the response
        /// - Assertion condition notBefore
        /// - Assertion condition notOnOrAfter
        /// - Assertion SubjectConfimationData notOnOrAfter
        /// - Response IssueInstant
        /// - Assertion IssueInstant
        /// </summary>
        /// <param name="response">The response which has to be controlled</param>
        /// <returns>true -> all times are correct, otherwise there will be an error thrown</returns>
        public bool CheckTime(Response response)
        {
            LogService.Log(LogService.LogType.Info, "SamlValidator - CheckTime called");
            TimeZone localZone = TimeZone.CurrentTimeZone;
            DateTime actualTime = localZone.ToUniversalTime(DateTime.Now);

            DateTime notBefore = response.Assertion.Conditions.NotBefore;
            DateTime notOnOrAfter = response.Assertion.Conditions.NotOnOrAfter;
            DateTime subNotOnOrAfter = response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter;
            DateTime responseIssueInstant = response.IssueInstant;
            DateTime assertionIssueInstant = response.Assertion.IssueInstant;

            if (DateTime.Compare(actualTime, notBefore) < 0)
                throw new SamlCommunicationException("Actual time is before Condition; " + notBefore.ToString(), SamlCommunicationType.SAMLVERIFICATION);
            if (DateTime.Compare(actualTime, notOnOrAfter) >= 0)
                throw new SamlCommunicationException("Actual time is equals or after Condition; " + notOnOrAfter.ToString(), SamlCommunicationType.SAMLVERIFICATION);
            if (DateTime.Compare(actualTime, responseIssueInstant) < 0)
                throw new SamlCommunicationException("Actual time is before Response-IssueInstant; " + responseIssueInstant.ToString(), SamlCommunicationType.SAMLVERIFICATION);
            if (DateTime.Compare(actualTime, assertionIssueInstant) < 0)
                throw new SamlCommunicationException("Actual time is before Assertion-IssueInstant; " + assertionIssueInstant.ToString(), SamlCommunicationType.SAMLVERIFICATION);
            if (DateTime.Compare(actualTime, subNotOnOrAfter) >= 0)
                throw new SamlCommunicationException("Actual time is equals or after SubjectConfirmationData time; " + subNotOnOrAfter.ToString(), SamlCommunicationType.SAMLVERIFICATION);

            LogService.Log(LogService.LogType.Info, "response time validation was successfully");

            return true;
        }
        #endregion CheckTime
    }
}
