from request_builder import RequestBuilder
from response_analyzer import ResponseAnalyzer
from threading import Thread

class EndpointAnalyzer:
    def __init__(self, helpers, callbacks, config_panel, logger):
        self.helpers = helpers
        self.callbacks = callbacks
        self.config = config_panel
        self.logger = logger
        self.request_builder = RequestBuilder(helpers)
        self.response_analyzer = ResponseAnalyzer(helpers)

    def analyze_endpoints(self, request_responses):
        task = EndpointAnalysisTask(
            self.helpers,
            self.callbacks,
            self.config,
            self.logger,
            self.request_builder,
            self.response_analyzer,
            request_responses
        )
        task.start()

class EndpointAnalysisTask(Thread):
    def __init__(self, helpers, callbacks, config, logger, request_builder, response_analyzer, request_responses):
        Thread.__init__(self)
        self.helpers = helpers
        self.callbacks = callbacks
        self.config = config
        self.logger = logger
        self.request_builder = request_builder
        self.response_analyzer = response_analyzer
        self.request_responses = request_responses

    def run(self):
        self.config.clear_table()
        self.config.add_log("Analyzing {} endpoints...".format(len(self.request_responses)))

        auth_header = self.config.get_auth_header_name()
        high_cred = self.config.get_high_cred()
        low_cred = self.config.get_low_cred()

        for rr in self.request_responses:
            try:
                request_info = self.helpers.analyzeRequest(rr)
                url = request_info.getUrl()
                method = request_info.getMethod()
                raw_request = rr.getRequest()
                protocol = url.getProtocol() == "https"
                http_service = self.helpers.buildHttpService(url.getHost(), url.getPort(), protocol)

                variants = self.request_builder.build_request_variants_from_raw(
                    raw_request, auth_header, high_cred, low_cred
                )

                responses = {}
                threads = []

                # For each endpoint, create 1 thread for each request variant
                for label, req_bytes in variants:
                    sender = RequestSender(
                        self.callbacks,
                        self.helpers,
                        self.config,
                        self.logger,
                        http_service,
                        req_bytes,
                        label,
                        url.getPath(),
                        responses
                    )
                    sender.start()
                    threads.append(sender)

                # Wait for all three variant threads to finish
                for t in threads:
                    t.join(timeout=10)  # prevent hanging forever

                # Analyze responses
                self.config.add_log("Analyzing responses for {}".format(url.getPath()))
                auth_required = self.response_analyzer.is_authentication_required(responses)
                authz_enforced = self.response_analyzer.is_authorization_enforced(responses)

                params = [param.getName() for param in request_info.getParameters()]
                param_str = ", ".join(params) if params else "-"

                self.config.add_endpoint_result(
                    url.getPath(),
                    method,
                    param_str,
                    "Yes" if auth_required else "No",
                    "Yes" if authz_enforced else "No",
                    responses
                )

                self.config.add_log("Finished analysis: {} {}".format(method, url.getPath()))

            except Exception as e:
                import traceback
                self.config.add_log("Error analyzing endpoint: {}".format(e))
                self.config.add_log(traceback.format_exc())

        self.config.add_log("Finished endpoint analysis.")

class RequestSender(Thread):
    def __init__(self, callbacks, helpers, config, logger, http_service, request_bytes, label, path, responses_dict):
        Thread.__init__(self)
        self.callbacks = callbacks
        self.helpers = helpers
        self.config = config
        self.logger = logger
        self.http_service = http_service
        self.request_bytes = request_bytes
        self.label = label
        self.path = path
        self.responses = responses_dict  # shared dict

    def run(self):
        try:
            self.config.add_log("Sending {} request to {}".format(self.label, self.path))
            resp = self.callbacks.makeHttpRequest(self.http_service, self.request_bytes)

            if resp is None or resp.getResponse() is None:
                self.config.add_log("No response for {} request to {}".format(self.label, self.path))
                return

            self.responses[self.label] = resp
            self.logger.log_request_response(resp)
            self.config.add_log("Got response for {} request to {}".format(self.label, self.path))

        except Exception as e:
            self.config.add_log("Error sending {} request to {}: {}".format(self.label, self.path, e))
