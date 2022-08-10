from pymisp import PyMISP
from pymisp import ExpandedPyMISP
import requests
import json
from TIAPILogging import TIAPILogging as logger

#add comments explaining what each of these constants are/what they do
TI_INDICATORS_URL =  'https://tigateway-ppe-wus2-fa.azurewebsites.net/{sentinel_workspace_id}/threatintelligence:upload-indicators'
# 'http://localhost:7071/afdc859e-6cc3-4bcb-a9ec-cd463fb1f4c1/threatintelligence:upload-indicators?api-version=2022-07-01'
#production_microsoft_oauth_url and dev_microsoft_oauth_url
PRODUCTION_INDICATORS_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
DEV_INDICATORS_URL = 'https://login.windows-ppe.net/{tenant}/oauth2/v2.0/token'
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
            # PRODUCTION_INDICATORS_URL.format(tenant=self.tenant), 
            # Temporary for dev
            DEV_INDICATORS_URL.format(tenant=self.tenant), 
            data=data
        ).json()['access_token']
        logger.debug_log("Access token created")   
        return access_token

    def publish(self, indicators) -> bool: 
        """Creates a post request to send indicators to the API. 

        Args:
            indicators (list of dictionaries): events to be used as the body of the request. 

        Returns:
            bool: True when the request is successful, false otherwise. 
        """
        body = {"value": indicators}
        body2 = json.dumps(body)
        print(body)
        token = self._get_access_token()
        response = requests.post(
            TI_INDICATORS_URL.format(sentinel_workspace_id=self.sentinel_workspace_id),
            headers={"Authorization": f"Bearer {token}"}, 
            json=body
            )
        logger.debug_log("Request sent")
        if(response.ok):
            logger.debug_log("Request successful")
            return True
        reason = response.reason
        logger.error_log("Request failed with error " + str(response.status_code) + ", " + format(reason))
        print(response.json())
        return True