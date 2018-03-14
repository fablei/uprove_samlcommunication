namespace uprove_samlcommunication.samlserialization
{ 
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:oasis:names:tc:SAML:2.0:metadata", IsNullable = false)]
    public partial class EntityDescriptor
    {

        private EntityDescriptorIDPSSODescriptor iDPSSODescriptorField;

        private EntityDescriptorOrganization organizationField;

        private EntityDescriptorContactPerson contactPersonField;

        private string idField;

        private string entityIDField;

        /// <remarks/>
        public EntityDescriptorIDPSSODescriptor IDPSSODescriptor
        {
            get
            {
                return this.iDPSSODescriptorField;
            }
            set
            {
                this.iDPSSODescriptorField = value;
            }
        }

        /// <remarks/>
        public EntityDescriptorOrganization Organization
        {
            get
            {
                return this.organizationField;
            }
            set
            {
                this.organizationField = value;
            }
        }

        /// <remarks/>
        public EntityDescriptorContactPerson ContactPerson
        {
            get
            {
                return this.contactPersonField;
            }
            set
            {
                this.contactPersonField = value;
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
        public string entityID
        {
            get
            {
                return this.entityIDField;
            }
            set
            {
                this.entityIDField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorIDPSSODescriptor
    {

        private EntityDescriptorIDPSSODescriptorKeyDescriptor[] keyDescriptorField;

        private EntityDescriptorIDPSSODescriptorSingleLogoutService[] singleLogoutServiceField;

        private string[] nameIDFormatField;

        private EntityDescriptorIDPSSODescriptorSingleSignOnService[] singleSignOnServiceField;

        private bool wantAuthnRequestsSignedField;

        private string protocolSupportEnumerationField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("KeyDescriptor")]
        public EntityDescriptorIDPSSODescriptorKeyDescriptor[] KeyDescriptor
        {
            get
            {
                return this.keyDescriptorField;
            }
            set
            {
                this.keyDescriptorField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("SingleLogoutService")]
        public EntityDescriptorIDPSSODescriptorSingleLogoutService[] SingleLogoutService
        {
            get
            {
                return this.singleLogoutServiceField;
            }
            set
            {
                this.singleLogoutServiceField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("NameIDFormat")]
        public string[] NameIDFormat
        {
            get
            {
                return this.nameIDFormatField;
            }
            set
            {
                this.nameIDFormatField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("SingleSignOnService")]
        public EntityDescriptorIDPSSODescriptorSingleSignOnService[] SingleSignOnService
        {
            get
            {
                return this.singleSignOnServiceField;
            }
            set
            {
                this.singleSignOnServiceField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public bool WantAuthnRequestsSigned
        {
            get
            {
                return this.wantAuthnRequestsSignedField;
            }
            set
            {
                this.wantAuthnRequestsSignedField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string protocolSupportEnumeration
        {
            get
            {
                return this.protocolSupportEnumerationField;
            }
            set
            {
                this.protocolSupportEnumerationField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorIDPSSODescriptorKeyDescriptor
    {

        private KeyInfo keyInfoField;

        private EntityDescriptorIDPSSODescriptorKeyDescriptorEncryptionMethod encryptionMethodField;

        private string useField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
        public KeyInfo KeyInfo
        {
            get
            {
                return this.keyInfoField;
            }
            set
            {
                this.keyInfoField = value;
            }
        }

        /// <remarks/>
        public EntityDescriptorIDPSSODescriptorKeyDescriptorEncryptionMethod EncryptionMethod
        {
            get
            {
                return this.encryptionMethodField;
            }
            set
            {
                this.encryptionMethodField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string use
        {
            get
            {
                return this.useField;
            }
            set
            {
                this.useField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IsNullable = false)]
    public partial class KeyInfo
    {

        private KeyInfoX509Data x509DataField;

        private KeyInfoRetrievalMethod retrievalMethodField;

        /// <remarks/>
        public KeyInfoX509Data X509Data
        {
            get
            {
                return this.x509DataField;
            }
            set
            {
                this.x509DataField = value;
            }
        }

        public KeyInfoRetrievalMethod RetrievalMethod
        {
            get
            {
                return this.retrievalMethodField;
            }
            set
            {
                this.retrievalMethodField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class KeyInfoX509Data
    {

        private string x509CertificateField;

        /// <remarks/>
        public string X509Certificate
        {
            get
            {
                return this.x509CertificateField;
            }
            set
            {
                this.x509CertificateField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorIDPSSODescriptorKeyDescriptorEncryptionMethod
    {

        private ushort keySizeField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2001/04/xmlenc#")]
        public ushort KeySize
        {
            get
            {
                return this.keySizeField;
            }
            set
            {
                this.keySizeField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Algorithm
        {
            get
            {
                return this.algorithmField;
            }
            set
            {
                this.algorithmField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorIDPSSODescriptorSingleLogoutService
    {

        private string bindingField;

        private string locationField;

        private string responseLocationField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Binding
        {
            get
            {
                return this.bindingField;
            }
            set
            {
                this.bindingField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Location
        {
            get
            {
                return this.locationField;
            }
            set
            {
                this.locationField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string ResponseLocation
        {
            get
            {
                return this.responseLocationField;
            }
            set
            {
                this.responseLocationField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorIDPSSODescriptorSingleSignOnService
    {

        private string bindingField;

        private string locationField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Binding
        {
            get
            {
                return this.bindingField;
            }
            set
            {
                this.bindingField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string Location
        {
            get
            {
                return this.locationField;
            }
            set
            {
                this.locationField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorOrganization
    {

        private EntityDescriptorOrganizationOrganizationName organizationNameField;

        private EntityDescriptorOrganizationOrganizationDisplayName organizationDisplayNameField;

        private EntityDescriptorOrganizationOrganizationURL organizationURLField;

        /// <remarks/>
        public EntityDescriptorOrganizationOrganizationName OrganizationName
        {
            get
            {
                return this.organizationNameField;
            }
            set
            {
                this.organizationNameField = value;
            }
        }

        /// <remarks/>
        public EntityDescriptorOrganizationOrganizationDisplayName OrganizationDisplayName
        {
            get
            {
                return this.organizationDisplayNameField;
            }
            set
            {
                this.organizationDisplayNameField = value;
            }
        }

        /// <remarks/>
        public EntityDescriptorOrganizationOrganizationURL OrganizationURL
        {
            get
            {
                return this.organizationURLField;
            }
            set
            {
                this.organizationURLField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorOrganizationOrganizationName
    {

        private string langField;

        private string valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(Form = System.Xml.Schema.XmlSchemaForm.Qualified, Namespace = "http://www.w3.org/XML/1998/namespace")]
        public string lang
        {
            get
            {
                return this.langField;
            }
            set
            {
                this.langField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorOrganizationOrganizationDisplayName
    {

        private string langField;

        private string valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(Form = System.Xml.Schema.XmlSchemaForm.Qualified, Namespace = "http://www.w3.org/XML/1998/namespace")]
        public string lang
        {
            get
            {
                return this.langField;
            }
            set
            {
                this.langField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorOrganizationOrganizationURL
    {

        private string langField;

        private string valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(Form = System.Xml.Schema.XmlSchemaForm.Qualified, Namespace = "http://www.w3.org/XML/1998/namespace")]
        public string lang
        {
            get
            {
                return this.langField;
            }
            set
            {
                this.langField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:SAML:2.0:metadata")]
    public partial class EntityDescriptorContactPerson
    {

        private string givenNameField;

        private string surNameField;

        private string emailAddressField;

        private string contactTypeField;

        /// <remarks/>
        public string GivenName
        {
            get
            {
                return this.givenNameField;
            }
            set
            {
                this.givenNameField = value;
            }
        }

        /// <remarks/>
        public string SurName
        {
            get
            {
                return this.surNameField;
            }
            set
            {
                this.surNameField = value;
            }
        }

        /// <remarks/>
        public string EmailAddress
        {
            get
            {
                return this.emailAddressField;
            }
            set
            {
                this.emailAddressField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string contactType
        {
            get
            {
                return this.contactTypeField;
            }
            set
            {
                this.contactTypeField = value;
            }
        }
    }


}
