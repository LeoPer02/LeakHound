class Leak:
    def __init__(self):
        self.sink = None
        self.dataTypes = {}
        self.paths = []  # List of paths, where each path is a list of PathElement instances

    def add_path(self, path):
        for elem in path:
            self.paths.append(elem)

    def get_path(self) -> list[list]:
        return self.paths

    def get_sink(self):
        return self.sink

    def get_datatypes(self):
        return self.dataTypes

    def add_sink(self, sink: str):
        self.sink = sink

    def add_data_type(self, method, dataType: str):
        self.dataTypes[method] = dataType
    def __repr__(self):
        paths_representation = "\n".join(
            " -> ".join(elem for elem in path) for path in self.paths
        )
        return f"Leak(sink={self.sink}, paths:\n{paths_representation}, Data Types:\n{self.dataTypes})"

