# import defaultdict because the indicators are originally returned as default dicts.
from collections import defaultdict
# import from MISPEventProvider.py to grab the events from the server
from MISPEventProvider import MISPEventProvider
# import from IndicatorConverter.py to convert events to STIX Indicators
from IndicatorConverter import IndicatorConverter as indicator_converter
# import from IndicatorPublisher.py to send events to Sentinel through the Upload Indicators API
from IndicatorPublisher import IndicatorPublisher
# import from TIAPILogging.py to log each section of the events
from TIAPILogging import TIAPILogging as logger

# delete this comment after updating all values within <>
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
        # This block of code grabs events from the MISP Server
        logger.debug_log("Fetching & parsing data from MISP")
        # misp_provider is the MISP object that we will use to get events. 
        misp_provider = MISPEventProvider(MISP_DOMAIN, MISP_KEY, MISP_VERIFYCERT)
        # events is a list of default_dicts. get_events takes all the events within the timerange specified on the MISP server
        events = misp_provider.get_events(lookBackTimeInDays=TIMERANGE)
        # by checking if the length of the events list is 0, or if the first event in the list has a length of zero, we can see if there were no events to be pulled, and end the function.
        if len(events) == 0 or (len(events) == 1 and len(events[0]) == 0):
            logger.error_log("ERROR: NO EVENTS PULLED FROM MISP")
            return
        logger.debug_log("Events successfully pulled from MISP ")

        # This block of code converts events to STIX Indicators
        logger.debug_log("Converting events to indicators")
        indicators = list() # this begins as an empty list, and will be populated with .json indicators in the loop below. 
        for event in events:
            try: 
                # indicator is a dictionary populated by the convert_event_to_indicator method in IndicatorConverter.py
                indicator = indicator_converter.convert_event_to_indicator(event)
                # indicator is added onto the previously existing list of indicators
                indicators.append(indicator) 
            except: 
                # we catch all exceptions from that method here. the indicators that don't work have their information dumped out for customers to use to fix and resend
                logger.exception_log("Indicator unable to be converted. Indicator information is dumped below. ")
                logger.debug_log("Continuing with future indicators now. ")
        logger.debug_log("Events succesfully converted to indicators")

        # This block of code sends the Indicators to Sentinel using the API
        logger.debug_log("Sending indicators to Threat Intelligence API")
        # indicator_publisher is an object of the IndicatorPublisher.py class 
        indicator_publisher = IndicatorPublisher(
                                            OAUTH_CONFIG['tenant'], 
                                            OAUTH_CONFIG['client_id'], 
                                            OAUTH_CONFIG['client_secret'], 
                                            OAUTH_CONFIG['scope'],
                                            SENTINEL_WORKSPACE_ID)
        # res is a boolean response to the publish method in IndicatorPublisher.py
        res = indicator_publisher.publish(indicators)
        if(not res):
            # if res is false, that means the indicators were not published and logs need to be checked
            logger.error_log("ERROR: INDICATORS NOT PUBLISHED")
        else:
            # if res is true, then the script has run successfully. 
            logger.debug_log("Indicators successfully uploaded")

    
