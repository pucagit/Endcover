class RequestBuilder:
    def __init__(self, helpers):
        self.helpers = helpers

    def build_request_variants_from_raw(self, raw_request_bytes, auth_header, high_value, low_value):
        """
        Takes a raw request (as bytes) and returns 3 variants with different auth headers.

        Returns:
            List of tuples: (label, request_bytes)
        """
        analyzed = self.helpers.analyzeRequest(raw_request_bytes)
        headers = list(analyzed.getHeaders())
        body_offset = analyzed.getBodyOffset()
        body = raw_request_bytes[body_offset:].tostring()

        # Remove any existing auth header
        stripped_headers = self._remove_auth_header(headers, auth_header)

        # Remove 304 headers if present
        stripped_headers = self.remove_304_headers(stripped_headers)

        # 3 variations
        variants = []

        # 1. No Auth
        variants.append((
            "Unauthenticated",
            self.helpers.buildHttpMessage(stripped_headers, body)
        ))

        # 2. Low-Priv
        low_headers = list(stripped_headers)
        if auth_header:
            low_headers.append("{}: {}".format(auth_header, low_value))
        variants.append((
            "Low-Priv",
            self.helpers.buildHttpMessage(low_headers, body)
        ))

        # 3. High-Priv
        high_headers = list(stripped_headers)
        if auth_header:
            high_headers.append("{}: {}".format(auth_header, high_value))
        variants.append((
            "High-Priv",
            self.helpers.buildHttpMessage(high_headers, body)
        ))

        return variants

    def _remove_auth_header(self, headers, header_name):
        """
        Removes any existing header that matches the given auth header name (case-insensitive) -> Return cleaned headers.
        """
        return [h for h in headers if not h.lower().startswith(header_name.lower() + ":")]
    
    def remove_304_headers(self, headers):
        """
        Removes headers that are typically present in 304 responses.
        This includes 'If-Modified-Since' and 'If-None-Match'.
        """
        clean_headers = []
        for header in headers:
            if not header.lower().startswith("if-modified-since") and not header.lower().startswith("if-none-match"):
                clean_headers.append(header)

        return clean_headers

