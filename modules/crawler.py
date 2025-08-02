from threading import Lock
from java.util.concurrent import Executors, TimeUnit

class PassiveCrawler:
    def __init__(self, callbacks, helpers, logger, config_panel):
        self.callbacks = callbacks
        self.helpers = helpers
        self.logger = logger
        self.config = config_panel

        self.default_api_keywords = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/auth/", "/user/", "/admin/"]

    def crawl(self):
        user_keyword = self.config.get_api_keyword()
        api_keywords = list(self.default_api_keywords)
        if user_keyword and user_keyword not in api_keywords:
            api_keywords.insert(0, user_keyword)

        site_map = self.callbacks.getSiteMap(None)
        seen = set()
        results = []
        lock = Lock()

        executor = Executors.newFixedThreadPool(10)

        for rr in site_map:
            executor.submit(lambda rr=rr: self._analyze_entry(rr, api_keywords, seen, results, lock))

        executor.shutdown()
        executor.awaitTermination(60, TimeUnit.SECONDS)

        self.logger.log("Crawled and found {} in-scope API endpoints.".format(len(results)))
        return results

    def _analyze_entry(self, rr, api_keywords, seen, results, lock):
        try:
            request_info = self.helpers.analyzeRequest(rr)
            url = request_info.getUrl()
            method = request_info.getMethod().upper()

            if not self.callbacks.isInScope(url):
                return
            if method == "OPTIONS":
                return
            if not self._looks_like_api(url.getPath(), api_keywords):
                return

            key = "{} {} {}".format(method, url.getPath(), url.getParameters())

            # Use a lock to ensure thread-safe access to shared seen and results
            with lock:
                if key in seen:
                    return
                seen.add(key)
                results.append(rr)

        except Exception as e:
            self.logger.error("Error parsing site map entry: {}".format(e))

    def _looks_like_api(self, path, keywords):
        path = path.lower()
        return any(keyword in path for keyword in keywords)
