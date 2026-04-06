"""Public baseline interface for zkSEC."""

from .context import SECURITY_CONTEXT_VERSION, known_adjacent_surfaces, load_security_context
from .routing import RoutedActionDecision, evaluate_adapter_action
from .security import SecurityDecision, assess_action, policy_receipt
from .execution import AdapterExecutionDirective, build_execution_directive
from .reporting import execution_audit_record
from .adapters import (
    AdapterCheckResult,
    AdapterContract,
    validate_action_against_adapter,
    kant_zk_pastebin_contract,
    zos_server_contract,
)

__all__ = [
    "SECURITY_CONTEXT_VERSION",
    "known_adjacent_surfaces",
    "load_security_context",
    "SecurityDecision",
    "assess_action",
    "policy_receipt",
    "AdapterCheckResult",
    "AdapterContract",
    "validate_action_against_adapter",
    "kant_zk_pastebin_contract",
    "zos_server_contract",
    "RoutedActionDecision",
    "evaluate_adapter_action",
    "AdapterExecutionDirective",
    "build_execution_directive",
    "execution_audit_record",
]
