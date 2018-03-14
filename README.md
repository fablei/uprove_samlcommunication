# SAML Communication
Please note that this repository is a result of the Master Thesis of the author at the BFH [8]. Newcomer and interested programmers, pls see the "Contributing" chapter as well.

This library was build to establish the communication between a U-Prove actor (e.g. the Issuer) - from the U-Prove Cryptographic Specification V1.1 Revision 3 [1] - and one from SAML [2] (e.g. IdP). The library allows the Issuer to send a signed authentication request to the IdP and to verify a received encrypted response sent by the IdP.

## Getting Started
Get yourself a local copy of this repository and open the solution file (uprove_samlcommunication.sln) in a Visual Studio 2015 (or a more recent version).

### Prerequisites
Before building the project, install the following dependencies:
* 	U-Prove JSON [3] (MIT license)
* 	Log4Net [4] (Apache License Version 2.0)
* 	Newtonsoft.JSON [5] (MIT license)

### Installing
* 	U-Prove JSON  
	You need to download and build the uprove_json [3] and include the build dependencies in the project.
* 	Log4Net  
	Open the Paket-Manager-Console and execute the following command (for further details, pls visit the official project webpage [7])
	```
	PM> Install-Package log4net
	```
* 	Newtonsoft.JSON  
	Open the Paket-Manager-Console and execute the following command (for further details, pls visit the official project webpage [7])
	```
	PM> Install-Package Newtonsoft.Json
	```

### Usage
You need to configurate the different paths, where the application can find the certificate or the metadata directory. These configurations where made in the App.config file of the project.

```
	<add key="KeystoreDirectoryPath" value="[PathToYourProjectFolder]\Keystore\" />
	<add key="KeystoreName" value="[YourKeystoreName].pfx" />
	<add key="KeystorePassword" value="[YourKeystorePassword]" />
	<add key="KeystoreFriendlyName" value="[YourKeystoreFriendlyName]" />
    
	<add key="MetadataDirectoryPath" value="[PathToYourProjectFolder]\Metadata\" />    
```

The library has five major classes (Cryptography, SamlArchiver, SamlCertificateController, SamlMetadataController, SamlValidator) which were all used by the main class (Saml2Controller). Following is a code example, how you could use the Saml2Controller class to send an validate SAML requests / responses.

```cs
	Saml2Controller controller = new Saml2Controller();
	controller.Init(keystorePath, keystorePassword, friendlyName, metadataDirectoryPath);
	string authnRequest = controller.CreateSamlAuthnRequest(authnRequestObject, signingAlgorithm);
	
	// send request
	string samlResponse = ...;
	
	try
	{
	
		controller.ReadResponse(samlResponse, relaystate, out responseAssertionAttributes))
		// samlResponse validation correct -> proceed
		
	} catch(Exception e) { throw new Exception("Error in response"); }
```
	
	

## Running the tests
Before running the tests, please make sure you have inserted the same configuration for the certificate into the App.config from the test project. In the "Test" menu of Visual Studio, select the "All Tests" from the "Run" submenu item. Note that a complete test run takes some time to complete. If you want to extend the tests, feel free to edit the "uprove_uprovecommunicationissuing_tests" project in the Visual Studio. The whole communication gets tested step by step and has dependencies to the previous message generation.

## Contributing
Contributors are always welcome. As information about U-Prove is only spread found the official webpage from Microsoft, I would like to build up a little community which is working with U-Prove and helps newcomer to get in touch easily. To do so, it would be nice if you could open a new "issue" at this [page](https://github.com/fablei/uprove_samlcommunication/issues) and select as kind -> task and fill in your project link.

If you're brand-new to the project and run into any blockers or problems, please open an [issue on this repository](https://github.com/fablei/uprove_samlcommunication/issues) and I would love to help you fix it for you!


## Author
* 	Bojan Leimer


## References

[1] https://www.microsoft.com/en-us/research/publication/u-prove-cryptographic-specification-v1-1-revision-3/

[2] http://saml.xml.org/saml-specifications

[3] https://github.com/fablei/uprove_json

[4] https://logging.apache.org/log4net/

[5] https://www.newtonsoft.com/json

[6] https://www.ti.bfh.ch/de/master/msc_engineering.html