from pymisp import PyMISP
from pymisp import ExpandedPyMISP
class MISPEventProvider: 

    """
    A class that handles getting the MISP Events from the server online. 
    """
    def __init__(self, misp_domain, misp_key, misp_verifycert):
        self.misp_domain = misp_domain
        self.misp_key = misp_key
        self.misp_verifycert = misp_verifycert

    def get_events(self, time=None):
        """
        Gets the events from the MISP server, splits them into separate events based on the filter, and returns the list of events. 
        Input: None
        Output: a list of events
        source: https://pymisp.readthedocs.io/en/latest/modules.html#pymisp
        """
        misp = ExpandedPyMISP(self.misp_domain, self.misp_key, self.misp_verifycert)
        if time == None:
            # returns all events ever, since time isn't specified
            return [event['Event'] for event in misp.search(controller='events', return_format='json')]
        events_by_timestamp = [
            # return every event since the time given in the parameter
            [event['Event'] for event in misp.search(controller='events', return_format='json', timestamp=time)] 
        ]
        return events_by_timestamp[0]

    #### delete when PR is complete
    def _pseudo_get_events():
        eventOne = {'id': '2', 'orgc_id': '1', 'org_id': '1', 'date': '2022-07-19', 'threat_level_id': '1', 'info': 'Information about our second indicator in existence.', 'published': False, 'uuid': 'c7092fd0-de39-4fca-b95c-0b568b166f13', 'attribute_count': '1', 'analysis': '1', 'timestamp': '1658341059', 'distribution': '1', 'proposal_email_lock': False, 'locked': False, 'publish_timestamp': '0', 'sharing_group_id': '0', 'disable_correlation': False, 'extends_uuid': '', 'protected': None, 'event_creator_email': 'admin@admin.test', 'Org': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Orgc': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Attribute': [{'id': '1', 'type': 'ip-src', 'category': 'Network activity', 'to_ids': False, 'uuid': '8e8b8fd1-4581-4849-be5f-8e5a32936fe9', 'event_id': '2', 'distribution': '5', 'timestamp': '1658341059', 'comment': '', 'sharing_group_id': '0', 'deleted': False, 'disable_correlation': False, 'object_id': '0', 'object_relation': None, 'first_seen': None, 'last_seen': None, 'value': '123.123.123.123', 'Galaxy': [], 'ShadowAttribute': []}], 'ShadowAttribute': [], 'RelatedEvent': [], 'Galaxy': [], 'Object': [], 'EventReport': [], 'CryptographicKey': []}
        eventTwo = {'id': '1', 'orgc_id': '1', 'org_id': '1', 'date': '2022-07-18', 'threat_level_id': '1', 'info': 'This is a test event', 'published': True, 'uuid': '10ea0177-3bcd-4e9d-8e92-b266ed345c6e', 'attribute_count': '0', 'analysis': '0', 'timestamp': '1658185233', 'distribution': '1', 'proposal_email_lock': False, 'locked': False, 'publish_timestamp': '1658185739', 'sharing_group_id': '0', 'disable_correlation': False, 'extends_uuid': '', 'protected': None, 'event_creator_email': 'admin@admin.test', 'Org': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Orgc': {'id': '1', 'name': 'ORGNAME', 'uuid': '473fc9b1-f7f6-4283-9489-e4f373f23473', 'local': True}, 'Attribute': [], 'ShadowAttribute': [], 'RelatedEvent': [], 'Galaxy': [], 'Object': [], 'EventReport': [], 'CryptographicKey': []}
        events = [eventOne, eventTwo]
        return events
