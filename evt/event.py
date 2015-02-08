class Event:

    def __init__(self, datetime, event_id, computer_name, user_sid, user, description, lifetime, device_instance_id):

        self.datetime = datetime
        self.event_id = event_id
        self.computer_name = computer_name
        self.user_sid = user_sid
        self.user = user
        self.description = description
        self.lifetime = lifetime
        self.device_instance_id = device_instance_id


