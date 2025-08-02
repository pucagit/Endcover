class Logger:
    def __init__(self, stdout, helpers=None, callbacks=None):
        self.stdout = stdout
        self.helpers = helpers
        self.callbacks = callbacks

    def log(self, msg):
        self.stdout.write("[INFO] " + str(msg) + "\n")

    def warn(self, msg):
        self.stdout.write("[WARN] " + str(msg) + "\n")

    def error(self, msg):
        self.stdout.write("[ERROR] " + str(msg) + "\n")

    def log_request_response(self, req_resp):
        """
        Logs an existing IHttpRequestResponse object into Burp's Logger tab.
        """
        if not self.callbacks:
            self.warn("Logger is missing callbacks: cannot log request/response")
            return

        try:
            # Save as temp-backed object (optional but efficient)
            temp_resp = self.callbacks.saveBuffersToTempFiles(req_resp)

            # Log to Site Map / Logger tab
            self.callbacks.addToSiteMap(temp_resp)

        except Exception as e:
            self.error("Failed to log request/response: " + str(e))


