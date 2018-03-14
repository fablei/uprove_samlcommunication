namespace uprove_samlcommunication.samlserialization
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:protocol", IsNullable = false)]
    public partial class AuthnRequest
    {

        private string issuerField;

        private AuthnRequestNameIDPolicy nameIDPolicyField;

        private string assertionConsumerServiceURLField;

        private byte attributeConsumingServiceIndexField;

        private string destinationField;

        private bool forceAuthnField;

        private string idField;

        private System.DateTime issueInstantField;

        private string protocolBindingField;

        private decimal versionField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:assertion")]
        public string Issuer
        {
            get
            {
                return this.issuerField;
            }
            set
            {
                this.issuerField = value;
            }
        }

        /// <remarks/>
        public AuthnRequestNameIDPolicy NameIDPolicy
        {
            get
            {
                return this.nameIDPolicyField;
            }
            set
            {
                this.nameIDPolicyField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string AssertionConsumerServiceURL
        {
            get
            {
                return this.assertionConsumerServiceURLField;
            }
            set
            {
                this.assertionConsumerServiceURLField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public byte AttributeConsumingServiceIndex
        {
            get
            {
                return this.attributeConsumingServiceIndexField;
            }
            set
            {
                this.attributeConsumingServiceIndexField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Destination
        {
            get
            {
                return this.destinationField;
            }
            set
            {
                this.destinationField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public bool ForceAuthn
        {
            get
            {
                return this.forceAuthnField;
            }
            set
            {
                this.forceAuthnField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string ID
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public System.DateTime IssueInstant
        {
            get
            {
                return this.issueInstantField;
            }
            set
            {
                this.issueInstantField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string ProtocolBinding
        {
            get
            {
                return this.protocolBindingField;
            }
            set
            {
                this.protocolBindingField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public decimal Version
        {
            get
            {
                return this.versionField;
            }
            set
            {
                this.versionField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:protocol")]
    public partial class AuthnRequestNameIDPolicy
    {

        private bool allowCreateField;

        private string formatField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public bool AllowCreate
        {
            get
            {
                return this.allowCreateField;
            }
            set
            {
                this.allowCreateField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Format
        {
            get
            {
                return this.formatField;
            }
            set
            {
                this.formatField = value;
            }
        }
    }
}