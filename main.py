import sys
from burp import IBurpExtender, ITab, IExtensionStateListener
from java.awt.event import ActionListener # type: ignore
from javax.swing import JFileChooser # type: ignore

# Add your extension root directory if needed (adjust this path)
sys.path.append("D:\\Tools\\Endcover")

# Custom modules
from ui.config_panel import ConfigPanel
from utils.logger import Logger
from utils.csv_writer import CSVWriter
from core.endpoint_analyzer import EndpointAnalyzer
from modules.proxy_history import ProxyHistoryAnalyzer
from modules.crawler import PassiveCrawler

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()

        callbacks.setExtensionName("Endcover")
        callbacks.registerExtensionStateListener(self)

        # Logger
        self.logger = Logger(self._stdout, self._helpers, self._callbacks)
        self.logger.log("Extension loaded.")

        # GUI panel
        self._config_panel = ConfigPanel(callbacks)
        callbacks.addSuiteTab(self)

        # Wire Start button
        self._config_panel.start_button.addActionListener(StartAnalysisListener(self))

        # CSV Write button
        self._config_panel.save_button.addActionListener(SaveCsvListener(self))

        # Clear Results button
        self._config_panel.clear_button.addActionListener(ClearResultsListener(self))

        self.analyzer = EndpointAnalyzer(self._helpers, self._callbacks, self._config_panel, self.logger)
        self.logger.log("Endpoint Analyzer initialized.")

        self.proxy_analyzer = ProxyHistoryAnalyzer(self._callbacks, self._helpers, self.logger, self._config_panel)
        self.logger.log("Proxy History Analyzer initialized.")

        self.crawler = PassiveCrawler(self._callbacks, self._helpers, self.logger, self._config_panel)
        self.logger.log("Passive Crawler initialized.")

    def getTabCaption(self):
        return "Endcover"

    def getUiComponent(self):
        return self._config_panel.get_main_panel()

    def extensionUnloaded(self):
        self.logger.log("Extension unloaded.")

# Start Button Listener
class StartAnalysisListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        config = self.extender._config_panel
        helpers = self.extender._helpers

        config.clear_table()
        config.clear_log()
        config.add_log("Starting API Discovery...")

        all_endpoints = []
        seen_keys = set()  # For deduplication

        def add_unique_endpoints(endpoint_list):
            for rr in endpoint_list:
                try:
                    req_info = helpers.analyzeRequest(rr)
                    method = req_info.getMethod()
                    url = req_info.getUrl()
                    key = "{} {}".format(method, url.getPath())

                    if key not in seen_keys:
                        seen_keys.add(key)
                        all_endpoints.append(rr)
                except Exception as e:
                    config.add_log("Error processing endpoint: {}".format(e))

        if config.is_crawling_enabled():
            config.add_log("Crawling target scope...")
            crawl_endpoints = self.extender.crawler.crawl()
            add_unique_endpoints(crawl_endpoints)

        if config.is_proxy_history_enabled():
            config.add_log("Analyzing proxy history...")
            proxy_endpoints = self.extender.proxy_analyzer.extract_endpoints()
            add_unique_endpoints(proxy_endpoints)

        config.add_log("Running endpoint authorization analysis...")
        self.extender.analyzer.analyze_endpoints(all_endpoints)

        config.add_log("API discovery complete.")

# Save CSV Listener
class SaveCsvListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        config = self.extender._config_panel
        logger = self.extender.logger
        rows = config.get_all_table_rows()

        if not rows:
            config.add_log("No data to export.")
            return

        file_chooser = JFileChooser()
        result = file_chooser.showSaveDialog(config.get_main_panel())

        if result == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".csv"):
                file_path += ".csv"

            writer = CSVWriter(logger)
            writer.write_results(file_path, rows)
            config.add_log("Results saved to: " + file_path)

# Clear Results Listener
class ClearResultsListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, event):
        config = self.extender._config_panel
        config.clear_table()
        config.clear_log()
        config.add_log("Results cleared.")