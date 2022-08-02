from collections import defaultdict
from MISPEventProvider import MISPEventProvider
from IndicatorConverter import IndicatorConverter as indicator_converter
from IndicatorPublisher import IndicatorPublisher

OAUTH_CONFIG = {
    # 'tenant': '72f988bf-86f1-41af-91ab-2d7cd011db47',   ##Production
    # 'client_id': '2785e766-9011-4e0c-871c-91d4d0b7dde8', 
    # 'client_secret': 'pT68Q~PxGNsbYEkgZGIPqCLcCzhmqNk5EffK4aZU', 
    # 'scope': 'https://management.azure.com/.default'

    'tenant': 'f686d426-8d16-42db-81b7-ab578e110ccd', ## Dev
    'client_id': '81616c92-ccbd-4873-9f02-1499a6eb2504', 
    'client_secret': '9tZ8Q~kkWkaE6bSZr.7n1uZ-eNQeST8FQ3nnGbm1', 
    'scope': 'https://management.azure.com/.default'
}
MISP_KEY = 'bhMRSoZKdDG6CB9B1x2dx48pXVAmqggjl0Czg4sj'
MISP_DOMAIN = 'https://20.115.210.151/'
MISP_VERIFYCERT = False
TIMERANGE = "7d"

class MISPSampleRunner:
    """
    This MISPSampleRunner class puts together the three sections of the project. 
    The first section is contained in MISPEventProvider.py, which gathers the events from the misp server. 
    The second section is contained in IndicatorConverter.py, which converts the events into the indicator type. 
    The third and final section is contained in SendIndicatorsAPI.py, which sends the converted indicators to the Threat Intelligence API. 
    The run() method contains everything necessary to complete this project. 
    """
    def run(): 
        """
        Gets the events from MISP, converts them to STIX Indicators, and uploads to the Threat Intelligence API. 
        """

        # get event from misp
        print('fetching & parsing data from misp...')
        misp_provider = MISPEventProvider(MISP_DOMAIN, MISP_KEY, MISP_VERIFYCERT)
        events = misp_provider.get_events(time=TIMERANGE)
        # events = MISPEventProvider._pseudo_get_events() #REMOVE AT END. 
        if len(events) == 0 or (len(events) == 1 and len(events[0]) == 0):
            print("No events. ")
            return
        # converts event to indicator 
        print('converting events to indicators...')
        indicators = list() # this begins as an empty list, and will be populated with .json indicators in the loop below. 
        for event in events:
            indicator = indicator_converter.convert_event_to_indicator(event)
            indicators.append(indicator) 

        # publish the indicator using the API
        print('sending indicators to Threat Intelligence API...')
        indicator_publisher = IndicatorPublisher(
                                            OAUTH_CONFIG['tenant'], 
                                            OAUTH_CONFIG['client_id'], 
                                            OAUTH_CONFIG['client_secret'], 
                                            OAUTH_CONFIG['scope'])
        res = indicator_publisher.publish(indicators)
        if(not res):
            print("FAIL!")
        else:
            print("SUCCESS!")

    
