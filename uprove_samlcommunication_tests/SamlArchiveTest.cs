using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using uprove_samlcommunication;

namespace uprove_samlcommunication_tests
{
    [TestClass]
    public class SamlArchiveTest
    {
        [TestMethod]
        public void ArchiverEmptyTest()
        {
            SamlArchiver archiver = new SamlArchiver();

            try { archiver.GetArchivedObject("notthere"); }
            catch (SamlCommunicationException e) { Assert.IsTrue(true); }    // expected because no object in archiver
            catch (Exception e) { Assert.Fail(e.Message); }
        }

        [TestMethod]
        public void ArchiverExistingTest()
        {
            SamlArchiver archiver = new SamlArchiver();
            string key = "samlTest";
            string value = "this is the value of the samlTest";

            try
            {
                Assert.IsTrue(archiver.SetObjectToArchive(key, value));
                Assert.IsTrue(archiver.Exists(key));
                Assert.AreEqual(value, archiver.GetArchivedObject(key));
            }
            catch (SamlCommunicationException e) { Assert.Fail(e.Message); }
            catch (Exception e) { Assert.Fail(e.Message); }
        }
    }
}
