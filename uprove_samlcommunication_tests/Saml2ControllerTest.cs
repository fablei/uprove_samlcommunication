using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using uprove_samlcommunication;
using uprove_samlcommunication.samlserialization;

namespace uprove_samlcommunication_tests
{
    [TestClass]
    public class Saml2ControllerTest
    {
        //private string xmlResponseFilename = "SamlResponseSimpleSamlPHP.xml";
        private string xmlResponseFilename = "SAMLResponseParameterSimpleSamlPHP.txt";

        private string xmlMetadataFileHub = "metadata-hub.xml";
        private string responseFilenameHub = "SamlResponseHubEncrypted.xml";

        //[TestMethod]
        //// Test is not running because you should create the authn request first -> ID and authn request registered in the archiver -> and then receive
        //// the response to check the response (fails on line 112/113 in Saml2Controller.cs)
        //public void ReadAssertionResponseTest()
        //{
        //    try
        //    {
        //        string xmlString = ReadFile(xmlResponseFilename);
        //        Dictionary<string, ResponseAssertionAttribute> attr = new Dictionary<string, ResponseAssertionAttribute>();
        //        string relatestate = "";

        //        string keystorePath = ConfigurationManager.AppSettings.Get("KeystoreDirectoryPathSP") + ConfigurationManager.AppSettings.Get("KeystoreNameSP");
        //        string keystorePassword = ConfigurationManager.AppSettings.Get("KeystorePasswordSP");
        //        string friendlyName = ConfigurationManager.AppSettings.Get("KeystoreFriendlyNameSP");
        //        string metadataDirectoryPath = ConfigurationManager.AppSettings.Get("MetadataDirectoryPath");

        //        Saml2Controller saml = new Saml2Controller();
        //        saml.Init(keystorePath, keystorePassword, friendlyName, metadataDirectoryPath);

        //        bool valid = saml.ReadResponse(xmlString, relatestate, out attr);

        //        Assert.AreEqual("Max", attr["surname"].Values[0]);
        //        Assert.AreEqual("Mustermann", attr["givenname"].Values[0]);
        //        Assert.AreEqual("student", attr["uid"].Values[0]);

        //        Assert.IsTrue(true);
        //    }
        //    catch (Exception e)
        //    {
        //        Assert.Fail();
        //    }
        //}

        [TestMethod]
        public void RemoveEncryptedAssertionTest()
        {
            try
            {
                // https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd

                Saml2Controller controller = new Saml2Controller();
                Saml2Serializer serializer = new Saml2Serializer();

                string keystorePath = ConfigurationManager.AppSettings.Get("KeystoreDirectoryPathSP") + ConfigurationManager.AppSettings.Get("KeystoreNameSP");
                string keystorePassword = ConfigurationManager.AppSettings.Get("KeystorePasswordSP");
                string friendlyName = ConfigurationManager.AppSettings.Get("KeystoreFriendlyNameSP");
                string metadataDirectoryPath = ConfigurationManager.AppSettings.Get("MetadataDirectoryPath");

                controller.Init(keystorePath, keystorePassword, friendlyName, metadataDirectoryPath);

                string xml = ReadFile(responseFilenameHub);
                Response response = serializer.ConvertXMLToResponseObject(xml);

                controller.RemoveEncryptedAssertion(response);

                Assert.IsNotNull(response.Assertion);
            }
            catch (Exception e)
            {
                Assert.Fail(e.Message);
            }
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
