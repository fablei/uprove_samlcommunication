using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Xml.Serialization;

namespace uprove_samlcommunication.samlserialization
{
    public class Saml2Serializer
    {
        /// <summary>
        /// Returns the Attributes from the given Response
        /// check fist if the response is valid or not!
        /// </summary>
        /// <param name="response">Response in which the attributes are</param>
        /// <returns>attributes from the response</returns>
        public Dictionary<string, ResponseAssertionAttribute> GetAttributes(Response response)
        {
            // read attributes
            Dictionary<string, ResponseAssertionAttribute> attributesDictionary = new Dictionary<string, ResponseAssertionAttribute>();
            foreach (AssertionAttribute assertionAttr in response.Assertion.AttributeStatement)
            {
                attributesDictionary.Add(assertionAttr.Name, new ResponseAssertionAttribute()
                { Key = assertionAttr.Name, NameFormat = assertionAttr.NameFormat, Values = assertionAttr.AttributeValue });
            }

            return attributesDictionary;
        }

        /// <summary>
        /// Returns the Attributes from the given Response
        /// check fist if the response is valid or not!
        /// </summary>
        /// <param name="response">Response in which the attributes are</param>
        /// <returns>attributes from the response</returns>
        public Dictionary<string, ResponseAssertionAttribute> GetAttributes(string xmlResponse)
        {
            return GetAttributes(ConvertXMLToResponseObject(xmlResponse));
        }

        // http://stackoverflow.com/questions/11447529/convert-an-object-to-an-xml-string

        public AuthnRequest ConvertXMLToAuthnRequestObject(string xml)
        {
            // http://stackoverflow.com/questions/67959/net-xml-serialization-gotchas
            XmlSerializer serializer = new XmlSerializer(typeof(AuthnRequest));
            StringReader reader = new StringReader(xml);
            return (AuthnRequest)serializer.Deserialize(reader);
        }

        public EntityDescriptor ConvertXMLToEntityDescriptorObject(string xml)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(EntityDescriptor));
            StringReader reader = new StringReader(xml);
            return (EntityDescriptor)serializer.Deserialize(reader);
        }

        public Response ConvertXMLToResponseObject(string xml)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(Response));
            StringReader reader = new StringReader(xml);
            return (Response)serializer.Deserialize(reader);
        }

        public Assertion ConvertXMLToAssertionObject(string xml)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(Assertion));
            StringReader reader = new StringReader(xml);
            return (Assertion)serializer.Deserialize(reader);
        }

        public string ConvertObjectToXML(AuthnRequest authnRequest)
        {
            StringWriter writer = new StringWriter();
            XmlSerializer serializer = new XmlSerializer(authnRequest.GetType());
            serializer.Serialize(writer, authnRequest);

            return writer.ToString();
        }


        // http://stackoverflow.com/questions/12090403/how-do-i-correctly-prepare-an-http-redirect-binding-saml-request-using-c-sharp

        /// <summary>
        /// Deflating and Base64 encoding
        /// </summary>
        /// <param name="toBeDeflate">string which should be deflated</param>
        /// <returns>Deflated and Base64 encoded content</returns>
        public string Deflate(string toBeDeflate, out string saml)
        {
            saml = string.Format(toBeDeflate, Guid.NewGuid());
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(saml);

            string zipped;
            using (var output = new MemoryStream())
            {
                using (var zip = new DeflateStream(output, CompressionMode.Compress))
                    zip.Write(bytes, 0, bytes.Length);

                zipped = Convert.ToBase64String(output.ToArray());
            }
            return zipped;
        }

        /// <summary>
        /// Base64 decode and inflate
        /// </summary>
        /// <param name="toBeInflate"></param>
        /// <returns>Content of the deflated object</returns>
        public string Inflate(string toBeInflate)
        {
            string unzipped = "";
            try
            {
                using (var input = new MemoryStream(Convert.FromBase64String(toBeInflate)))
                using (var unzip = new DeflateStream(input, CompressionMode.Decompress))
                using (var reader = new StreamReader(unzip, System.Text.Encoding.UTF8))
                    unzipped = reader.ReadToEnd();
            }
            catch(Exception e)
            {
                throw new SamlCommunicationException("Infalte went wrong", e, SamlCommunicationType.SAMLSERIALIZATION);
            }
            return unzipped;
        }
    }
}