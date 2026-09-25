class CompileError(Exception):
    def __init__(self, message: str, line: int | None = None):
        self.line = line
        text = f"Line {line}: {message}" if line is not None else message
        super().__init__(text)
