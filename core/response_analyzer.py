class ResponseAnalyzer:
    def __init__(self, helpers):
        self.helpers = helpers

    def is_authentication_required(self, responses):
        """
        Determine if the endpoint requires authentication.
        If unauthenticated response is significantly different or returns 401/403, auth is required.
        """
        unauth = responses.get("Unauthenticated")
        low = responses.get("Low-Priv") or responses.get("High-Priv")

        if not unauth or not unauth.getResponse():
            return False  # Cannot decide

        unauth_status = self._get_status_code(unauth)
        if unauth_status in [401, 403]:
            return True

        if low and low.getResponse():
            return self._compare_bodies(unauth, low) 

        return False

    def is_authorization_enforced(self, responses):
        """
        Determine if authorization is enforced (i.e., difference between low-priv and high-priv).
        """
        low = responses.get("Low-Priv")
        high = responses.get("High-Priv")

        if not low or not high or not low.getResponse() or not high.getResponse():
            return False  # Cannot determine

        low_status = self._get_status_code(low)
        high_status = self._get_status_code(high)

        if high_status != low_status:
            return True

        return self._compare_bodies(low, high)

    def _get_status_code(self, rr):
        try:
            response_info = self.helpers.analyzeResponse(rr.getResponse())
            return response_info.getStatusCode()
        except Exception:
            return 0

    def _compare_bodies(self, rr1, rr2):
        """
        Compare response bodies - naive comparison (can be improved).
        Returns True if they differ significantly.
        """
        body1 = self._get_body(rr1)
        body2 = self._get_body(rr2)

        if body1 is None or body2 is None:
            return False

        if len(body1) == 0 and len(body2) > 0:
            return True

        if abs(len(body1) - len(body2)) > 50:
            return True

        return body1 != body2

    def _get_body(self, rr):
        try:
            response = rr.getResponse()
            if not response:
                return None
            info = self.helpers.analyzeResponse(response)
            body_bytes = response[info.getBodyOffset():]
            return self.helpers.bytesToString(body_bytes).strip()
        except Exception:
            return None
