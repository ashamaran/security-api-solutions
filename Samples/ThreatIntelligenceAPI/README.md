# NOT FULLY UPDATED, DO NOT EDIT. 
# MISP to Microsoft Threat Intelligence API Script
The <b> MISP to Microsoft Threat Intelligence API Script </b> enables you to connect your custom threat indicators and make them available in the following Microsoft products: **[Azure Sentinel](https://azure.microsoft.com/en-us/services/azure-sentinel/)**, **[Microsoft Defender ATP](https://www.microsoft.com/en-us/microsoft-365/windows/microsoft-defender-atp/)**
<br/>
The script provides clients with MISP instances to migrate threat indicators to the [Microsoft Threat Intelligence API](INSERT LINK). 

For more information on Microsoft Threat Intelligence API visit [Microsoft Threat Intelligence API](INSERT LINK). <br/>
For more information on MISP visit https://www.misp-project.org/.

## Prerequisites
Before installing the sample:
* Install Python 3.x version from https://www.python.org/.
* Ensure MISP Server is installed and can be connected to - refer to MISP install details at https://www.misp-project.org/download/  

**For more info on how to register app, see "App Registration" section.**

## Getting Started
After the prerequisites are installed or met, perform the following steps to use these scripts:

1. Download or clone this repository.
1. Go to directory `security-api-solutions/Samples/ThreatIntelligenceAPI`
1. Install dependencies.  In the command line, run `pip3 install requests requests-futures pymisp` 
1. To run script, go to the root directory of ThreatIntelligenceAPI and enter `python3 script.py` in the command line. 

## App Registration
To configure the sample, you'll need to register a new application in the Microsoft [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
Follow these steps to register a new application:
1. Sign in to the [Application Registration Portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) using either your personal or work or school account.

1. Choose **New registration**.

1. Enter an application name, and choose **Register**.

1. Next you'll see the overview page for your app. Copy and save the **Application Id** field. You will need it later to complete the configuration process.

1. Under **Certificates & secrets**, choose **New client secret** and add a quick description. A new secret will be displayed in the **Value** column. Copy this password. You will need it later to complete the configuration process and it will not be shown again.
    
1. Modify the MISPSampleRunner.py to update the constants at the top of the file. 
```
OAUTH_CONFIG = {
    'tenant': '<tenant id>',
    'client_id': '<client id>',
    'client_secret': '<client secret>',
    'scope': '<scope>'
}
MISP_KEY = '<misp_key>'
MISP_DOMAIN = '<misp_domain>'
MISP_VERIFYCERT = False
TIMERANGE = "<time_range>"
```

Once changes are complete, save the MISPSampleRunner file. After you've completed these steps and have received [admin consent](ADD LINK HERE) for your app, you'll be able to run the script.py sample as covered below.


#### Misp Key
The Misp Key is required to fetch data from your Misp instance. 
It can be found in the event actions menu under automation on the website of the Misp instance.

`misp_key = '<misp key>'`

#### Misp Domain
Misp Domain is the base URL of your MISP instance.

#### Misp Verify Cert
This gives you the option to choose if python should validate the certificate of the misp instance. This allows ease within testing environments.
It is recommended to use a valid SSL cert in production and change this value to True.

`misp_verifycert = False` 


## Contributing
If you'd like to contribute to this sample, see [CONTRIBUTING.MD](https://github.com/microsoftgraph/security-api-solutions/blob/master/CONTRIBUTING.md).

This project has adopted the Microsoft Open Source Code of Conduct. For more information, see the Code of Conduct FAQ or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Questions and comments
We'd love to get your feedback about the MISP to Microsoft Graph Security script. You can send your questions and suggestions to us in the Issues section of this repository.


UPDATE THIS.
Your feedback is important to us. Connect with us on [Stack Overflow](https://stackoverflow.com/questions/tagged/microsoft-graph-security). On Stack Overflow tag your questions with [threat-intelligence-api].

### Copyright
Copyright (c) 2022 Microsoft. All rights reserved.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information, see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
