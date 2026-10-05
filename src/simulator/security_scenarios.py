from datetime import timedelta


class SecurityScenarioGenerator:

    def __init__(self, users, devices, applications):

        self.users = users
        self.devices = devices
        self.applications = applications

        # ---------------------------------------------------------
        # Lookup dictionaries
        # ---------------------------------------------------------

        self.user_map = {
            user["user_id"]: user
            for user in users
        }

        self.device_map = {
            device["device_id"]: device
            for device in devices
        }

        self.application_map = {
            application["application_id"]: application
            for application in applications
        }

        # ---------------------------------------------------------
        # Map each user to their devices
        # ---------------------------------------------------------

        self.user_devices = {}

        for device in devices:
            self.user_devices.setdefault(
                device["user_id"],
                []
            ).append(device)

    # =============================================================
    # Helper methods
    # =============================================================

    def _get_user_device(self, user_id):
        """
        Return one valid device belonging to the user.
        """

        devices = self.user_devices.get(user_id, [])

        if not devices:
            raise ValueError(
                f"No device found for user: {user_id}"
            )

        return devices[0]

    def _get_different_user_device(self, user_id):
        """
        Return a device belonging to another user.

        Used for scenarios where we intentionally want to
        simulate an unfamiliar device.
        """

        for device in self.devices:

            if device["user_id"] != user_id:
                return device

        raise ValueError(
            "Could not find a device belonging to another user."
        )

   

    # =============================================================
    # Scenario 1: Brute-force login
    # =============================================================

    def brute_force_login(
        self,
        user_id,
        start_time,
        attempts=20
    ):
        """
        Generate repeated failed login attempts for one user.

        The attempts occur within a short time window,
        simulating a brute-force authentication pattern.
        """

        device = self._get_user_device(user_id)

        events = []

        for i in range(attempts):

            events.append({

                "event_id":
                    f"BRUTE-{user_id}-{i:03d}",

                "user_id":
                    user_id,

                "timestamp":
                    start_time + timedelta(seconds=i * 20),

                "ip_address":
                    "185.220.101.10",

                "country":
                    "Unknown",

                "city":
                    "Unknown",

                "device_id":
                    device["device_id"],

                "authentication_method":
                    "PASSWORD",

                "login_status":
                    "FAILED",

                "failure_reason":
                    "INVALID_PASSWORD"
            })

        return events

    # =============================================================
    # Scenario 2: Impossible travel
    # =============================================================

    def impossible_travel(
        self,
        user_id,
        start_time
    ):
        """
        Generate two successful authentication events
        from geographically distant locations within
        an unrealistic travel time.
        """

        device = self._get_user_device(user_id)

        events = [

            {
                "event_id":
                    f"TRAVEL-{user_id}-001",

                "user_id":
                    user_id,

                "timestamp":
                    start_time,

                "ip_address":
                    "103.21.244.10",

                "country":
                    "India",

                "city":
                    "Pune",

                "device_id":
                    device["device_id"],

                "authentication_method":
                    "PASSWORD",

                "login_status":
                    "SUCCESS",

                "failure_reason":
                    None
            },

            {
                "event_id":
                    f"TRAVEL-{user_id}-002",

                "user_id":
                    user_id,

                "timestamp":
                    start_time + timedelta(minutes=10),

                "ip_address":
                    "185.60.216.10",

                "country":
                    "United Kingdom",

                "city":
                    "London",

                "device_id":
                    device["device_id"],

                "authentication_method":
                    "PASSWORD",

                "login_status":
                    "SUCCESS",

                "failure_reason":
                    None
            }
        ]

        return events

    # =============================================================
    # Scenario 3: New device login
    # =============================================================

    def new_device_login(
        self,
        user_id,
        start_time
    ):
        """
        Simulate a user logging in from a device that belongs
        to another user.

        This intentionally creates a behavioral anomaly while
        keeping the device itself valid in the device inventory.
        """

        known_device = self._get_user_device(user_id)

        new_device = self._get_different_user_device(user_id)

        events = [

            {
                "event_id":
                    f"NEWDEVICE-{user_id}-001",

                "user_id":
                    user_id,

                "timestamp":
                    start_time,

                "ip_address":
                    "172.16.50.25",

                "country":
                    "India",

                "city":
                    "Mumbai",

                "device_id":
                    new_device["device_id"],

                "authentication_method":
                    "PASSWORD",

                "login_status":
                    "SUCCESS",

                "failure_reason":
                    None
            }
        ]

        return events

    # =============================================================
    # Scenario 4: After-hours activity
    # =============================================================

    def after_hours_activity(
        self,
        user_id,
        start_time
    ):
        """
        Generate successful authentication and access activity
        during unusual hours.
        """

        device = self._get_user_device(user_id)

        application = self.applications[0]

        auth_event = {

            "event_id":
                f"AFTERHOURS-AUTH-{user_id}",

            "user_id":
                user_id,

            "timestamp":
                start_time,

            "ip_address":
                "10.20.30.40",

            "country":
                "India",

            "city":
                "Pune",

            "device_id":
                device["device_id"],

            "authentication_method":
                "PASSWORD",

            "login_status":
                "SUCCESS",

            "failure_reason":
                None
        }

        access_event = {

            "event_id":
                f"AFTERHOURS-ACCESS-{user_id}",

            "user_id":
                user_id,

            "timestamp":
                start_time + timedelta(minutes=5),

            "device_id":
                device["device_id"],

            "application_id":
                application["application_id"],

            "action":
                "LOGIN",

            "resource":
                "APPLICATION",

            "access_status":
                "SUCCESS"
        }

        return {
            "authentication": [auth_event],
            "access": [access_event]
        }

    # =============================================================
    # Scenario 5: Privilege escalation
    # =============================================================

    def privilege_escalation(
        self,
        user_id,
        start_time
    ):
        """
        Simulate a normal user receiving an elevated privilege.
        """

        privilege_event = {

            "event_id":
                f"PRIVESC-{user_id}-001",

            "user_id":
                user_id,

            "timestamp":
                start_time,

            "previous_role":
                "ANALYST",

            "new_role":
                "ADMINISTRATOR",

            "previous_privilege_level":
                2,

            "new_privilege_level":
                5,

            "change_reason":
                "UNAUTHORIZED_ROLE_CHANGE",

            "approved":
                False
        }

        return [privilege_event]

    # =============================================================
    # Scenario 6: Sensitive resource access
    # =============================================================

    def sensitive_resource_access(
        self,
        user_id,
        start_time
    ):
        """
        Simulate access to a highly sensitive application
        followed by a risky action.
        """

        device = self._get_user_device(user_id)

        application = self.applications[0]

        access_event = {

            "event_id":
                f"SENSITIVE-{user_id}-001",

            "user_id":
                user_id,

            "timestamp":
                start_time,

            "device_id":
                device["device_id"],

            "application_id":
                application["application_id"],

            "action":
                "DOWNLOAD",

            "resource":
                "SENSITIVE_DATA",

            "access_status":
                "SUCCESS"
        }

        return [access_event]

    # =============================================================
    # Scenario 7: Combined high-risk scenario
    # =============================================================

    def combined_high_risk(
        self,
        user_id,
        start_time
    ):
        """
        Combine multiple suspicious behaviors for the same user.

        Signals:
            1. Brute-force login
            2. After-hours authentication
            3. Privilege escalation
            4. Sensitive resource access
        """

        # ---------------------------------------------------------
        # Brute-force activity
        # ---------------------------------------------------------

        brute_force_events = self.brute_force_login(
            user_id=user_id,
            start_time=start_time,
            attempts=20
        )

        # ---------------------------------------------------------
        # After-hours authentication
        # ---------------------------------------------------------

        after_hours_events = self.after_hours_activity(
            user_id=user_id,
            start_time=start_time + timedelta(minutes=10)
        )

        # ---------------------------------------------------------
        # Privilege escalation
        # ---------------------------------------------------------

        privilege_events = self.privilege_escalation(
            user_id=user_id,
            start_time=start_time + timedelta(minutes=15)
        )

        # ---------------------------------------------------------
        # Sensitive resource access
        # ---------------------------------------------------------

        sensitive_events = self.sensitive_resource_access(
            user_id=user_id,
            start_time=start_time + timedelta(minutes=20)
        )

        return {

            "authentication":
                brute_force_events
                + after_hours_events["authentication"],

            "access":
                after_hours_events["access"]
                + sensitive_events,

            "privilege":
                privilege_events
        }