"""Offensive AI Red Team Agent Package (PBL6 v3.0)."""

from .evasion import TAMPER_CATALOG, EvasionEngine
from .pentest_advisor import PentestDQNAdvisor
from .planner import AttackPlanner
from .recon import APIReconAgent, ReconReport
from .synthesizer import OpenAPIPayloadSynthesizer, SynthesizedTestCase
from .tools import DispatchResult, HttpDispatcher

__all__ = [
    "APIReconAgent",
    "ReconReport",
    "AttackPlanner",
    "EvasionEngine",
    "TAMPER_CATALOG",
    "PentestDQNAdvisor",
    "OpenAPIPayloadSynthesizer",
    "SynthesizedTestCase",
    "DispatchResult",
    "HttpDispatcher",
]
