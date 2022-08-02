from pymisp import PyMISP
from pymisp import ExpandedPyMISP
import requests

TI_INDICATORS_URL = 'https://tigateway-dev-ev2test-ezavczd2eghfbxa2.z01.azurefd.net/afdc859e-6cc3-4bcb-a9ec-cd463fb1f4c1/threatintelligence:upload-indicators'

class IndicatorPublisher: 
    """
    A class that handles sending indicators to the Threat Intelligence API. 
    """
    def __init__(self, tenant, client_id, client_secret, scope):
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope

    def _get_access_token(self) -> str: 
        """
        Get access token necessary for accessing the server to upload indicators and download indicators. 
        Input:  self
        Output: the access token as a string. 
        """
        data = {
            'client_id': self.client_id,
            'scope': self.scope,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        access_token = requests.post(
            # two lines below should be constants: MICROSOFT_OAUTH_PRODUCTION_URL = ... MICROSOFT_OAUTH_DEV_URL = ...
            # f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',  # Production code
            f'https://login.windows-ppe.net/{self.tenant}/oauth2/v2.0/token', # Temporary for dev
            data=data
        ).json()['access_token']   
        return access_token


    def publish(self, parsed_events) -> bool: 
        """
        To send indicators to the API, we need to create a post request. This post request is done below, given the events to place into the body. 
        Input: events to send to the API in the form of a list of dictionaries (Each dictionary is one JSON, or indicator)
        Output: When working properly, true. Otherwise, false. 
        """
        body = {'value': parsed_events}
        token = IndicatorPublisher._get_access_token(self)
        response = requests.post(
            TI_INDICATORS_URL,
            headers={"Authorization": f"Bearer {token}"}, 
            json=body
            )
        if("200" in str(response)):
            return True
        return False