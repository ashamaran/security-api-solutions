# import defaultdict because the indicators are originally returned as default dicts.
from collections import defaultdict
# import datetime to grab timestamp values from events
import datetime
# import timedelta to easily add 90 days to find valid_until values
from datetime import timedelta
# import json to switch format from defaultdict to dict/json
import json
# import from TIAPILogging.py to log each section of the events
from TIAPILogging import TIAPILogging as logger

# the TYPE of the event being handled is an indicator, because that is what we take from the MISP server
TYPE = "indicator"
# the PATTERN_TYPE of the event is STIX, since we are converting events to STIX Indicators
PATTERN_TYPE = "stix"

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
        # the indicator will be saved/returned as a defaultdict, initialized below
        indicator = defaultdict(list) 
        # parses pattern
        for attr in event['Attribute']:  # set this under Network Activity on the MISP Server. 
            # we parse the indicator pattern into the format of: [<type>:value = '<type-value>']
            # this is shown in the lines below. 
            # if the type/pattern is not given, an exception is thrown since it is a required value.
            if attr['type'] == 'ip-src': 
                indicator["pattern"] = '[ipv4-addr:value = \'' + attr['value'] + '\']' 
            elif attr['type'] == 'domain': 
                indicator["pattern"] = '[domain-name:value = \'' + attr['value'] + '\']'
        if indicator["pattern"] == "":
            logger.exception_log("EXCEPTION: MISSING REQUIRED PATTERN VALUE. ")
            raise AttributeError("The required attribute is not populated due to the field (\"pattern\") not being given in the event")
         # parses spec_version
        indicator["spec_version"] = "2.1"
        # parses id
        # event.get("key", "") takes the value from the specific key in the dictionary, and returns an empty string if it's not populated. if there is no value, we throw an exception
        id = event.get("uuid", "") 
        if id == "":
            logger.exception_log("EXCEPTION: MISSING REQUIRED ID VALUE. ")
            raise AttributeError("The required attribute is not populated due to the field (\"uuid\") not being given in the event")
        indicator["id"] = "indicator--" + id
        # parses created
        indicator["created"] = event.get("date", "") 
        if indicator["created" ] == "":
            logger.exception_log("EXCEPTION: MISSING REQUIRED CREATED VALUE. ")
            raise AttributeError("The required attribute is not populated due to the field (\"date\") not being given in the event")
        # parses valid_from
        indicator["valid_from"] = event.get("date", "") 
        if indicator["valid_from" ] == "":
            logger.exception_log("EXCEPTION: MISSING REQUIRED VALID_FROM VALUE. ")
            raise AttributeError("The required attribute is not populated due to the field (\"date\") not being given in the event")
        # parses modified
        modified = event.get("timestamp", "")
        if modified == "":
            logger.exception_log("EXCEPTION: MISSING REQUIRED MODIFIED VALUE. ")
            raise AttributeError("The required attribute is not populated due to the field (\"timestamp\") not being given in the event")
        # the modified value is given as a string. we convert it to an integer to then grab the datetime object from it so it is easily readable by humans. it is then turned back into a string once it is a date. 
        indicator["modified"] = str(datetime.datetime.fromtimestamp(int(modified)))
        # parses type
        indicator["type"] = TYPE
        # parses pattern_type
        indicator["pattern_type"] = PATTERN_TYPE
        logger.debug_log("Required indicator values parsed")

        # these are optional properties that can be added to
        for attr in event['Attribute']:   
            # parses name
            if attr['type'] == 'full-name': # set this under Person on the MISP Server.
                indicator["name"] = attr['value']
            if attr['type'] == 'comment': # set this under Other on the MISP Server
                indicator["confidence"] = int(attr['value'])
        # parses description
        indicator["description"] = event.get("info", "") 
        # parses valid_until
        # typically, the indicate is valid_until 90 days after the current date. this gives that value. 
        indicator["valid_until"] = str(datetime.date.today() + timedelta(days=90)) 
        indicator["tags"] = [tag['name'].strip() for tag in event.get("Tag", [])] 
        for tag in indicator["tags"]:
            # parses traffic light protocol
            # if the tlp value is given, we take that and save it. if it is not, we automatically give it a tlp of "red"
            if "tlp:" in tag: 
                indicator["tlpLevel"] = tag.split(":")[1]
            if "tlpLevel" not in indicator:
                indicator["tlpLevel"] = "red"
                # parses diamond model
            if "diamond-model:" in tag: 
                indicator["diamondModel"] = tag.split(":")[1]
        # parses created_by
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
        # json.dumps takes in a json object and returns a string. json.loads() takes in a string and returns a .json object. 
        # this return takes in the indicator as a default dict, switches it to a string, and switches the string to a .json/dictionary. 
        return json.loads(json.dumps(indicator))