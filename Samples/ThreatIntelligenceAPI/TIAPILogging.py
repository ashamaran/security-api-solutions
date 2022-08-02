import inspect

class TIAPILogging:
    """Wrapper of TI API Indicator Logger"""
    """
    Normally when we log, we want to log as much as possible because this could be the only info we get when we're trying to fix problems in the future


    """


    def _generate_log_message(self, msg):
        """Add details to message: class and method name of callers.
        Args:
            msg (str): Message
        Returns:
            string: Message wil caller infomation
        """
        stack = inspect.stack()
        caller_class = stack[2][0].f_locals.get("self", None)
        if caller_class is None:
            caller_class_name = "Static or Class Method"
        else:
            caller_class_name = caller_class.__class__.__name__

        caller_method_name = stack[2][0].f_code.co_name
        return f"[{caller_class_name}].[{caller_method_name}] {msg}"

    def logDebug(self, msg):
        """Logs debug

        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        self._socml_logger.logDebug(self._generate_log_message(msg))

    def logInfo(self, msg, properties=None):
        """Logs info

        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        self._socml_logger.logInfo(self._generate_log_message(msg))

    def logWarning(self, msg, properties=None):
        """Logs warning

        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        self._socml_logger.logWarning(self._generate_log_message(msg))

    def logError(self, msg, properties=None):
        """Logs error

        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        self._socml_logger.logError(self._generate_log_message(msg))

    def logException(self, exception, properties=None):
        """Logs error

        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        self._socml_logger.logException(exception, self._add_additional_properties(properties))

    def trackMetric(self, metricName, value, properties=None):
        """Sends a metric. Metrics can be used for monitoring and alerting in ICM.

        Args:
                metricName (str): metric name
                value (double): metric value
                properties (dict(str)): the set of custom properties for log. (defaults to: None)
        """
        self._socml_logger.trackMetric(metricName, value, self._add_additional_properties(properties))
