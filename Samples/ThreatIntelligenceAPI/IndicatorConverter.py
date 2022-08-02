from collections import defaultdict
import datetime
from datetime import timedelta
import json

class IndicatorConverter: 
    """A class that handles converting events to Stix Indicators for use in the Threat Intelligence Indicator API
    """

    @staticmethod
    def _generate_indicator(event) -> defaultdict:
        """
        Sets up required indicator values, including: "type", "spec_version", "id", "created", "modified", "pattern", "pattern_type", and "valid_from"
        Sets up optional indicator values, which are not necessary to send an indicator but can be populated if the information is given
        Input:  indicator - the list to add required information to. 
                event - the event itself that is being parsed
        Output: defaultdict of all required indicator information. 
        """
        indicator = defaultdict(list) 
        for attr in event['Attribute']: # parses pattern
            if attr['type'] == 'ip-src': 
                indicator['pattern'] = 'ipv4-addr:value = \'' + attr['value'] + '\''
            elif attr['type'] == 'domain': 
                indicator['pattern'] = 'domain-name:value = \'' + attr['value'] + '\''
            else: 
                indicator['pattern'] = attr['type'] + ':value = \'' + attr['value'] + '\''
        indicator['spec_version'] = '2.1' # parses spec_version
        indicator['id'] = event.get("uuid", "") # parses id
        indicator['created'] = event.get("date", "") # parses created
        indicator['valid_from'] = event.get("date", "") # parses valid_from
        modified = int(event.get("timestamp", ""))
        indicator['modified'] = str(datetime.datetime.fromtimestamp(modified)) # parses modified
        indicator['type'] = 'indicator' # parses type
        indicator['pattern_type'] = 'stix' # parses pattern_type

        # these are optional properties that can be added to
        indicator['description'] = event.get("info", "") # parses description
        indicator['valid_until'] = str(datetime.date.today() + timedelta(days=90)) # parses valid_until
        indicator['tags'] = [tag['name'].strip() for tag in event.get("Tag", [])] 
        for tag in indicator['tags']:
            if 'tlp:' in tag: # parses traffic light protocol
                indicator['tlpLevel'] = tag.split(':')[1]
            if 'tlpLevel' not in indicator:
                indicator['tlpLevel'] = 'red'
            if 'diamond-model:' in tag: # parses diamond model
                indicator['diamondModel'] = tag.split(':')[1]
        return indicator
        
    @staticmethod
    def convert_event_to_indicator(event) -> dict:
        """
        Runs _generate_indicator(event) on an event, and converts it to .json format (dict) for returning. 
        Input:  event - the event itself being parsed
        Output: .json that can be used to upload an indicator to the API. 
        """
        indicator = IndicatorConverter._generate_indicator(event)
        return json.loads(json.dumps(indicator))

