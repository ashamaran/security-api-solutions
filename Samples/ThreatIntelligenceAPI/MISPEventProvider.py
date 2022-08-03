from pymisp import PyMISP
from pymisp import ExpandedPyMISP
from TIAPILogging import TIAPILogging as logger

class MISPEventProvider: 
    """
    A class that handles getting the MISP Events from the server online. 
    """
    def __init__(self, misp_domain, misp_key, misp_verifycert):
        self.misp_domain = misp_domain
        self.misp_key = misp_key
        self.misp_verifycert = misp_verifycert

    def get_events(self, lookBackTimeInDays=None):
        """Gets the events from the MISP server, splits them into separate events based on the filter, and returns the list of events. 

        Args:
            lookBackTimeInDays (String, optional): String consisting of a number and "d" for the number of days worth of indicators to give. "7d" would give the last 7 days worth of indicators/events. Defaults to None.

        Returns:
            A list of type dictionary: list of events from the MISP Server that can be iterated through. 
        """
        misp = ExpandedPyMISP(self.misp_domain, self.misp_key, self.misp_verifycert)
        logger.debug_log("Downloaded MISP Events Successfully")
        if lookBackTimeInDays == None:
            # returns all events ever, since time isn't specified
            logger.debug_log("All events returned, no time parameter")
            return [event['Event'] for event in misp.search(controller='events', return_format='json')]
        events_by_timestamp = [
            # return every event since the time given in the parameter
            [event['Event'] for event in misp.search(controller='events', return_format='json', timestamp=lookBackTimeInDays)] 
        ]
        logger.debug_log("Events from timestamp until now returned. ")
        return events_by_timestamp[0]

