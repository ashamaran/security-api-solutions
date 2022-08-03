from collections import defaultdict
from MISPEventProvider import MISPEventProvider
from IndicatorConverter import IndicatorConverter as indicator_converter
from IndicatorPublisher import IndicatorPublisher
from TIAPILogging import TIAPILogging as logger

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
SENTINEL_WORKSPACE_ID = "<Sentinel Workspace ID>"

class MISPSampleRunner:
    """
    This MISPSampleRunner class puts together the three sections of the project. 
    The first section is contained in MISPEventProvider.py, which gathers the events from the misp server. 
    The second section is contained in IndicatorConverter.py, which converts the events into the indicator type. 
    The third and final section is contained in SendIndicatorsAPI.py, which sends the converted indicators to the Threat Intelligence API. 
    The run() method contains everything necessary to complete this project. 
    """
    def run(): 
        """Gets the events from MISP, converts them to STIX Indicators, and uploads to the Threat Intelligence API. 
        """
        # get event from misp
        logger.debug_log("fetching & parsing data from MISP")
        misp_provider = MISPEventProvider(MISP_DOMAIN, MISP_KEY, MISP_VERIFYCERT)
        events = misp_provider.get_events(lookBackTimeInDays=TIMERANGE)
        if len(events) == 0 or (len(events) == 1 and len(events[0]) == 0):
            logger.debug_log("ERROR: NO EVENTS PULLED FROM MISP")
            return
        logger.debug_log("Events successfully pulled from MISP ")
        # converts event to indicator 
        logger.debug_log("converting events to indicators")
        indicators = list() # this begins as an empty list, and will be populated with .json indicators in the loop below. 
        for event in events:
            indicator = indicator_converter.convert_event_to_indicator(event)
            indicators.append(indicator) 
        logger.debug_log("Events succesffully converted to indicators")
        # publish the indicator using the API
        logger.debug_log("sending indicators to Threat Intelligence API")
        indicator_publisher = IndicatorPublisher(
                                            OAUTH_CONFIG['tenant'], 
                                            OAUTH_CONFIG['client_id'], 
                                            OAUTH_CONFIG['client_secret'], 
                                            OAUTH_CONFIG['scope'],
                                            SENTINEL_WORKSPACE_ID)
        res = indicator_publisher.publish(indicators)
        if(not res):
            logger.debug_log("ERROR: INDICATORS NOT PUBLISHED")
        else:
            logger.debug_log("Indicators successfully uploaded")

    
