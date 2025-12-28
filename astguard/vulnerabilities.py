"""Module containing dangerous functions and CWE definitions."""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class CWEEntry:
    """Data structure for storing CWE vulnerability information.

    Attributes:
        cwe_id: CWE identifier.
        name: Vulnerability name.
        description: Brief description of the vulnerability.
        severity: Severity level (HIGH, MEDIUM, LOW).
        patterns: List of function names or patterns associated with this vulnerability.
        recommendation: Remediation recommendation.
        risk: Description of exploitation risks.

    """

    cwe_id: str
    name: str
    description: str
    severity: SeverityLevel
    patterns: List[str]
    recommendation: str
    risk: str


# Dictionary mapping CWE identifiers to vulnerability information.
SOURCES = {
    "input",
    "os.getenv",
    "flask.request",
    "request.args",
    "request.form",
    "request.values",
    "request.json",
}

DANGEROUS_FUNCTIONS = {
    "CWE-94": CWEEntry(
        cwe_id="CWE-94",
        name="Code Injection",
        description="Использование eval(), exec(), compile() с недоверенным вводом",
        severity=SeverityLevel.HIGH,
        patterns=["eval", "exec", "compile"],
        recommendation=(
            "Использовать ast.literal_eval() для безопасного вычисления литералов"
        ),
        risk="Выполнение произвольного кода",
    ),
    "CWE-78": CWEEntry(
        cwe_id="CWE-78",
        name="Command Injection",
        description="Выполнение shell-команд без надлежащей санитизации ввода",
        severity=SeverityLevel.HIGH,
        patterns=["os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"],
        recommendation=(
            "Использовать subprocess.run() с shell=False и списком аргументов"
        ),
        risk="Инъекция shell-команды через параметры",
    ),
    "CWE-502": CWEEntry(
        cwe_id="CWE-502",
        name="Deserialization",
        description="Небезопасная десериализация объектов",
        severity=SeverityLevel.HIGH,
        patterns=["pickle.loads", "pickle.load", "yaml.unsafe_load", "yaml.load"],
        recommendation="Использовать JSON или другой безопасный формат сериализации",
        risk="Выполнение произвольного кода при десериализации",
    ),
    "CWE-22": CWEEntry(
        cwe_id="CWE-22",
        name="Path Traversal",
        description="Операции файловой системы с путями, контролируемыми пользователем",
        severity=SeverityLevel.MEDIUM,
        patterns=["open", "os.path.join"],
        recommendation="Валидировать пути и ограничивать доступ к директориям",
        risk="Несанкционированный доступ к файлам",
    ),
    "CWE-327": CWEEntry(
        cwe_id="CWE-327",
        name="Weak Cryptography",
        description="Использование устаревших криптографических примитивов",
        severity=SeverityLevel.MEDIUM,
        patterns=["hashlib.md5", "hashlib.sha1"],
        recommendation=(
            "Использовать современные алгоритмы, такие как SHA-256 или SHA-3"
        ),
        risk="Возможность взлома хеша или расшифровки данных",
    ),
    "CWE-798": CWEEntry(
        cwe_id="CWE-798",
        name="Hardcoded Credentials",
        description="Строки с паролями или ключами в исходном коде",
        severity=SeverityLevel.HIGH,
        patterns=["password", "secret", "token", "api_key"],
        recommendation="Использовать переменные окружения или менеджеры секретов",
        risk="Компрометация учетных данных",
    ),
    "CWE-489": CWEEntry(
        cwe_id="CWE-489",
        name="Debug Features",
        description="Отладочные функции в production-коде",
        severity=SeverityLevel.LOW,
        patterns=["debug=True"],
        recommendation="Отключить функции отладки в промышленных средах",
        risk="Раскрытие технической информации о системе",
    ),
    "CWE-89": CWEEntry(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="Конкатенация строк в SQL-запросах",
        severity=SeverityLevel.HIGH,
        patterns=["execute"],
        recommendation="Использовать параметризованные запросы",
        risk="Несанкционированное манипулирование базой данных",
    ),
    "CWE-611": CWEEntry(
        cwe_id="CWE-611",
        name="XML External Entities (XXE)",
        description="Небезопасная конфигурация XML-парсера",
        severity=SeverityLevel.MEDIUM,
        patterns=["xml.etree.ElementTree", "lxml.etree"],
        recommendation="Деактивировать обработку внешних сущностей в парсере",
        risk="Раскрытие файлов на сервере или SSRF",
    ),
}

# Mapping of functions to their CWE for fast lookup.
FUNCTION_TO_CWE = {}
for cwe in DANGEROUS_FUNCTIONS.values():
    for pattern in cwe.patterns:
        FUNCTION_TO_CWE[pattern] = cwe.cwe_id


@dataclass
class Finding:
    """Represents a discovered vulnerability with full information."""

    file_path: str
    line_number: int
    pattern: str
    function_name: Optional[str] = None
    cwe_details: Optional[CWEEntry] = None

    def __post_init__(self) -> None:
        """Automatically complement CWE data during initialization."""
        if not self.cwe_details:
            cwe_id = FUNCTION_TO_CWE.get(self.pattern)
            if cwe_id:
                self.cwe_details = DANGEROUS_FUNCTIONS.get(cwe_id)
