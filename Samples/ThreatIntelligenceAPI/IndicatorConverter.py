from collections import defaultdict
import datetime
from datetime import timedelta
import json
from TIAPILogging import TIAPILogging as logger

TYPE = 'indicator'
PATTERN_TYPE = 'stix'

class IndicatorConverter: 
    """A class that handles converting events to Stix Indicators for use in the Threat Intelligence Indicator API
    """

    @staticmethod
    def _generate_indicator(event) -> defaultdict:
        """Sets up required indicator values, including: "type", "spec_version", "id", "created", "modified", "pattern", "pattern_type", and "valid_from", and optional values, which are not necessary to send an indicator but can be populated if the information is given

        Args:
            event (dictionary): the event that will be converted into an indicator

        Returns:
            defaultdict: the indicator as a default dict that contains all required information, and all optional information that exists. 
        """
        indicator = defaultdict(list) 
        # parses pattern
        for attr in event['Attribute']: 
            if attr['type'] == 'ip-src': 
                indicator['pattern'] = 'ipv4-addr:value = \'' + attr['value'] + '\''
            elif attr['type'] == 'domain': 
                indicator['pattern'] = 'domain-name:value = \'' + attr['value'] + '\''
            else: 
                indicator['pattern'] = attr['type'] + ':value = \'' + attr['value'] + '\''
         # parses spec_version
        indicator['spec_version'] = '2.1'
        # parses id
        indicator['id'] = event.get("uuid", "") 
        if indicator['id' ] == "":
    
        # parses created
        indicator['created'] = event.get("date", "") 
        if indicator['created' ] == "":
            logger.debug_log("ERROR: MISSING REQUIRED CREATED VALUE. ")
        # parses valid_from
        indicator['valid_from'] = event.get("date", "") 
        if indicator['valid_from' ] == "":
            logger.debug_log("ERROR: MISSING REQUIRED VALID_FROM VALUE. ")
        # parses modified
        modified = event.get("timestamp", "")
        if modified == "":
            logger.debug_log("ERROR: MISSING REQUIRED MODIFIED VALUE. ")
        indicator['modified'] = str(datetime.datetime.fromtimestamp(int(modified)))
        # parses type
        indicator['type'] = TYPE
        # parses pattern_type
        indicator['pattern_type'] = PATTERN_TYPE
        logger.debug_log("Required indicator values parsed")
        
        # these are optional properties that can be added to
        # parses description
        indicator['description'] = event.get("info", "") 
        # parses valid_until
        indicator['valid_until'] = str(datetime.date.today() + timedelta(days=90)) 
        indicator['tags'] = [tag['name'].strip() for tag in event.get("Tag", [])] 
        for tag in indicator['tags']:
            # parses traffic light protocol
            if 'tlp:' in tag: 
                indicator['tlpLevel'] = tag.split(':')[1]
            if 'tlpLevel' not in indicator:
                indicator['tlpLevel'] = 'red'
                # parses diamond model
            if 'diamond-model:' in tag: 
                indicator['diamondModel'] = tag.split(':')[1]
        logger.debug_log("Optional indicator values parsed")
        return indicator
        
    @staticmethod
    def convert_event_to_indicator(event) -> dict:
        """Runs _generate_indicator(event) on an event, and converts it to .json format (dict) for returning. 

        Args:
            event (dict): the event itself being parsed

        Returns:
            dict: .json that can be used to upload an indicator to the API. 
        """
        indicator = IndicatorConverter._generate_indicator(event)
        logger.debug_log("Event converted.")
        return json.loads(json.dumps(indicator))

