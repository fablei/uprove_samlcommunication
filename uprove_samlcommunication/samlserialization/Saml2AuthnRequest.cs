using System;

namespace uprove_samlcommunication.samlserialization
{
    public class Saml2AuthnRequest
    {
        // properties
        public string AssertionConsumerServiceURL { get; set; }
        public int AttributeConsumingServiceIndex { get; set; }
        public string Destination { get; set; }
        public bool ForceAuthn { get; set; }
        public string ID { get; set; }
        public DateTime IssueInstant { get; set; }
        public string ProviderName { get; set; }
        public string Issuer { get; set; }

        public string ToXML()
        {
            return String.Format(GetAssertionXML(), new string[]{
                AssertionConsumerServiceURL, AttributeConsumingServiceIndex.ToString(),
                Destination, ForceAuthn.ToString().ToLower(), ID, IssueInstant.ToString("yyyy-MM-ddTHH:mm:ss.fffK"), ProviderName, Issuer});
        }

        private string GetAssertionXML()
        {
            return "<saml2p:AuthnRequest AssertionConsumerServiceURL=\"{0}\" "
                    + "AttributeConsumingServiceIndex=\"{1}\" "
                    + "Destination=\"{2}\" "
                    + "ForceAuthn=\"{3}\" "
                    + "ID=\"{4}\" "
                    + "IssueInstant=\"{5}\" "
                    + "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "
                    + "ProviderName=\"{6}\" "
                    + "Version=\"2.0\" "
                    + "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"> "
                    + "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">{7}</saml2:Issuer>"
                    + "</saml2p:AuthnRequest>";
        }

    }





    
}
