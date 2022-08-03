import inspect

class TIAPILogging:
    """Wrapper of TI API Indicator Logger for use in handling errors as they arise."""
    def _generate_log_message(msg):
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

    def debug_log(msg):
        """Logs debug
        Args:
                msg (str): the message
        """
        print(TIAPILogging._generate_log_message(msg))

    def warning_log(msg, properties=None):
        """Logs warning
        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        print(TIAPILogging.warning_log(_generate_log_message(msg)))

    def error_log(msg, properties=None):
        """Logs error
        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        print(_generate_log_message(msg))

    def exception_log(exception, properties=None):
        """Logs error
        Args:
                msg (str): the message
                properties:- custom dimensions for the log
        """
        print(TIAPILogging.exception_log(exception))