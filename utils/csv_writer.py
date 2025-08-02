class CSVWriter:
    def __init__(self, logger):
        self.logger = logger

    def write_results(self, filepath, results):
        """
        Writes a list of endpoint result rows to a CSV file.

        Args:
            filepath: full path to output CSV file
            results: list of rows, each a tuple of:
                (Endpoint, Method, Parameters, Auth Required, AuthZ Enforced)
        """
        try:
            with open(filepath, "w") as f:
                header = "Endpoint,HTTP Method,Parameters,Authentication Required,Authorization Enforced\n"
                f.write(header)
                for row in results:
                    f.write(",".join('"{}"'.format(cell) for cell in row) + "\n")

            self.logger.log("CSV report written to: {}".format(filepath))

        except Exception as e:
            self.logger.error("Failed to write CSV: {}".format(e))
