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

    #### delete when PR is complete
    def _pseudo_get_events():
        eventOne = {'id': '8', 'orgc_id': '1', 'org_id': '1', 'date': '2022-08-02', 'threat_level_id': '1', 'info': 'test event 3', 'published': False, 'uuid': '86ec1f47-e14f-4b6f-af7c-e72bdd928cfa', 'attribute_count': '3', 'analysis': '0', 'timestamp': '1659991125', 'distribution': '1', 'proposal_email_lock': True, 'locked': False, 'publish_timestamp': '0', 'sharing_group_id': '0', 'disable_correlation': False, 'extends_uuid': '', 'protected': None, 'event_creator_email': 'admin@admin.test', 'Org': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Orgc': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Attribute': [{'id': '5', 'type': 'domain', 'category': 'Network activity', 'to_ids': False, 'uuid': '5d73319a-122c-4dfe-b6bf-7e36ea8e0d54', 'event_id': '3', 'distribution': '5', 'timestamp': '1659989321', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': 'microsoft.com', 'Galaxy': [], 'ShadowAttribute': []}, {'id': '6', 'type': 'full-name', 'category': 'Person', 'to_ids': False, 'uuid': 'ef1980be-d806-46f8-b08c-86f067f9211f', 'event_id': '3', 'distribution': '0', 'timestamp': '1659990263', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': 'DemoIndicatorOne', 'Galaxy': [], 'ShadowAttribute': []}, {'id': '9', 'type': 'comment', 'category': 'Other', 'to_ids': False, 'uuid': '58c637e2-f1cc-47e5-911f-f62517dcb339', 'event_id': '3', 'distribution': '5', 'timestamp': '1659991125', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': '67', 'Galaxy': [], 'ShadowAttribute': []}], 'ShadowAttribute': [], 'RelatedEvent': [], 'Galaxy': [], 'Object': [], 'EventReport': [], 'CryptographicKey': []}
        eventTwo = {'id': '7', 'orgc_id': '1', 'org_id': '1', 'date': '2022-08-05', 'threat_level_id': '1', 'info': 'Demo Indicator', 'published': False, 'uuid': '4d4671fa-d169-42ee-9cb5-08c97b9bbd6b', 'attribute_count': '3', 'analysis': '0', 'timestamp': '1659991106', 'distribution': '1', 'proposal_email_lock': False, 'locked': False, 'publish_timestamp': '0', 'sharing_group_id': '0', 'disable_correlation': False, 'extends_uuid': '', 'protected': None, 'event_creator_email': 'admin@admin.test', 'Org': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Orgc': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Attribute': [{'id': '2', 'type': 'ip-src', 'category': 'Network activity', 'to_ids': False, 'uuid': '9d264291-0aef-4131-b51b-431a52c080fc', 'event_id': '6', 'distribution': '5', 'timestamp': '1659984468', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': '192.168.10.100', 'Galaxy': [], 'ShadowAttribute': []}, {'id': '7', 'type': 'full-name', 'category': 'Person', 'to_ids': False, 'uuid': 'e3932e1e-0a62-4ccb-84e3-d3c5e5d36197', 'event_id': '6', 'distribution': '5', 'timestamp': '1659990292', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': 'DemoIndicatorTwo', 'Galaxy': [], 'ShadowAttribute': []}, {'id': '8', 'type': 'comment', 'category': 'Other', 'to_ids': False, 'uuid': '8c550a29-105b-424c-a401-9bcf679fba7d', 'event_id': '6', 'distribution': '5', 'timestamp': '1659991106', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': '80', 'Galaxy': [], 'ShadowAttribute': []}], 'ShadowAttribute': [], 'RelatedEvent': [], 'Galaxy': [], 'Object': [], 'EventReport': [], 'CryptographicKey': []}
        events = [eventOne, eventTwo]
        return events
