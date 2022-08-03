from pymisp import PyMISP
from pymisp import ExpandedPyMISP
import requests
from TIAPILogging import TIAPILogging as logger

TI_INDICATORS_URL = 'https://tigateway-dev-ev2test-ezavczd2eghfbxa2.z01.azurefd.net/afdc859e-6cc3-4bcb-a9ec-cd463fb1f4c1/threatintelligence:upload-indicators'

class IndicatorPublisher: 
    """
    A class that handles sending indicators to the Threat Intelligence API. 
    """
    def __init__(self, tenant, client_id, client_secret, scope, sentinel_workspace_id):
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.sentinel_workspace_id = sentinel_workspace_id

    def _get_access_token(self) -> str: 
        """ Get access token necessary for accessing the server to upload indicators and download indicators. 

        Returns:
            str: the access token as a string. 
        """
        data = {
            'client_id': self.client_id,
            'scope': self.scope,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        access_token = requests.post(
             # Production code
            # f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token', 
            # Temporary for dev
            f'https://login.windows-ppe.net/{self.tenant}/oauth2/v2.0/token', 
            data=data
        ).json()['access_token']
        logger.debug_log("access token created")   
        return access_token

    def publish(self, indicators) -> bool: 
        """Creates a post request to send indicators to the API. 

        Args:
            indicators (list of dictionaries): events to be used as the body of the request. 

        Returns:
            bool: True when the request is successful, false otherwise. 
        """
        body = {'value': indicators}
        token = self._get_access_token()
        response = requests.post(
            'https://tigateway-dev-ev2test-ezavczd2eghfbxa2.z01.azurefd.net/' + self.sentinel_workspace_id + '/threatintelligence:upload-indicators',
            headers={"Authorization": f"Bearer {token}"}, 
            json=body
            )
        logger.debug_log("request sent")
        if(response.ok):
            logger.debug_log("request successful")
            return True
        reason = response.reason
        logger.debug_log("request failed with error " + response.status_code + ", " + format(reason))
        return False