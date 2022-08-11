# import requests so we can send http requests to the API
import requests
# import json so we can work with/return json values when necessary
import json
# import from TIAPILogging.py to log each section of the events
from TIAPILogging import TIAPILogging as logger

# TI Indicators URL is the URL that we upload the indicators to. This is our connection to the Upload Indicators API
TI_INDICATORS_URL =  'https://tigateway-ppe-wus2-fa.azurewebsites.net/{sentinel_workspace_id}/threatintelligence:upload-indicators'
# Production Microsoft OAUTH URL is the URL that we use to grab an authorization token. This allows us to log into the API to upload indicators. 
PRODUCTION_MICROSOFT_OAUTH_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'

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
        # to get an access token, we need to send a post request with all the data necessary in a dictionary. that is what is done in the data below. 
        data = {
            'client_id': self.client_id,
            'scope': self.scope,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        # the post request is sent with the authorization url (with the tenant populated), and the data from the constructor. we grab the token from the returned json.
        access_token = requests.post(
            PRODUCTION_MICROSOFT_OAUTH_URL.format(tenant=self.tenant), 
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
        # the body of this http request is a dictionary with a key of "value". the value of the key "value" is a list of .jsons. 
        body = {"value": indicators}
        # the token is found through the method above.
        token = self._get_access_token()
        # the post request is sent with the API url (with the workspace_id populated), the token given as a header, and the body given as the json. 
        response = requests.post(
            TI_INDICATORS_URL.format(sentinel_workspace_id=self.sentinel_workspace_id),
            headers={"Authorization": f"Bearer {token}"}, 
            json=body
            )
        logger.debug_log("Request sent")
        # if the result of that request is .ok, meaning it returned a 200 value, the request properly sent. 
        if(response.ok):
            logger.debug_log("Request successful")
            return True
        # if it didn't we print out the http value, the reason, and the .json response. 
        reason = response.reason
        logger.error_log("Request failed with error " + str(response.status_code) + ", " + format(reason))
        print("JSON RESPONSE ", response.json())
        return False