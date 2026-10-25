import os
from pathlib import Path
from typing import List, Optional, Union
from maltrace.contracts.schemas import NormalizedEvent, BehaviorClaim, FamilyPrediction


def classify_malware_family(
    events: List[NormalizedEvent],
    claims: List[BehaviorClaim],
    model_dir: Optional[Union[str, Path]] = None
) -> FamilyPrediction:
    """
    Classify malware family using trained model adapter if model_dir is specified and artifacts exist,
    otherwise fallback gracefully to deterministic heuristic rules.
    """
    target_model_dir: Optional[Path] = None

    if model_dir:
        target_model_dir = Path(model_dir)
    elif os.environ.get("MODEL_DIR"):
        target_model_dir = Path(os.environ["MODEL_DIR"])

    if target_model_dir and (target_model_dir / "model.joblib").exists():
        try:
            from maltrace.models.trainer import predict_events_with_model
            return predict_events_with_model(events, target_model_dir)
        except Exception:
            pass

    # FALLBACK HEURISTIC RULES CLASSIFIER
    claim_cats = {c.category for c in claims}
    all_args_str = " ".join([str(e.safe_arguments).lower() for e in events])
    api_names_str = " ".join([e.api_name.lower() for e in events])
    combined_sig = f"{all_args_str} {api_names_str}"

    # Rule: Wiper (HermeticWiper, CaddyWiper)
    if any(k in combined_sig for k in ["hermetic", "physicaldrive", "rawdisk", "drvdump", "wiper", "mbr_overwrite"]):
        wiper_evts = [
            e.event_id for e in events
            if any(k in str(e.safe_arguments).lower() for k in ["physicaldrive", "rawdisk", "drvdump", "hermetic", "wiper"])
        ]
        return FamilyPrediction(
            family_name="Wiper.HermeticWiper",
            confidence=0.94,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_WIPER_RAW_DISK_CORRUPTION",
            supporting_evidence_ids=wiper_evts[:10] if wiper_evts else [events[0].event_id]
        )

    # Specific Ransomware Variants
    if any(k in combined_sig for k in ["lockbit", "lb3", ".lockbit", "restore-my-files.txt"]):
        lb_evts = [
            e.event_id for e in events
            if any(k in str(e.safe_arguments).lower() for k in ["lockbit", "restore-my-files", ".lockbit", "vssadmin"])
        ]
        return FamilyPrediction(
            family_name="Ransomware.LockBit",
            confidence=0.93,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_LOCKBIT_RANSOMWARE_ENCRYPTION",
            supporting_evidence_ids=lb_evts[:10] if lb_evts else [events[0].event_id]
        )

    if any(k in combined_sig for k in ["blackcat", "alphv"]):
        bc_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["blackcat", "alphv", "vssadmin"])]
        return FamilyPrediction(
            family_name="Ransomware.BlackCat",
            confidence=0.91,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_BLACKCAT_RANSOMWARE_ENCRYPTION",
            supporting_evidence_ids=bc_evts[:10] if bc_evts else [events[0].event_id]
        )

    if any(k in combined_sig for k in ["phobos", "id[", ".phobos"]):
        ph_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["phobos", ".phobos", "id["])]
        return FamilyPrediction(
            family_name="Ransomware.Phobos",
            confidence=0.90,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_PHOBOS_RANSOMWARE_ENCRYPTION",
            supporting_evidence_ids=ph_evts[:10] if ph_evts else [events[0].event_id]
        )

    # Specific Stealers
    if any(k in combined_sig for k in ["agenttesla", "smtp.live.com", "mail.smtp", "keylog", "ftp_exfil"]):
        at_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["agenttesla", "smtp", "keylog", "passwords"])]
        return FamilyPrediction(
            family_name="Stealer.AgentTesla",
            confidence=0.91,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_AGENTTESLA_KEYLOGGER_SMTP_EXFIL",
            supporting_evidence_ids=at_evts[:10] if at_evts else [events[0].event_id]
        )

    if any(k in combined_sig for k in ["lumma", "wallet.dat", "metamask", "solana_vault"]):
        lm_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["lumma", "wallet", "metamask", "passwords"])]
        return FamilyPrediction(
            family_name="Stealer.Lumma",
            confidence=0.90,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_LUMMA_WALLET_CREDENTIAL_GRAB",
            supporting_evidence_ids=lm_evts[:10] if lm_evts else [events[0].event_id]
        )

    if any(k in combined_sig for k in ["vidar", "t.me/", "telegram_c2"]):
        vd_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["vidar", "telegram", "passwords"])]
        return FamilyPrediction(
            family_name="Stealer.Vidar",
            confidence=0.89,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_VIDAR_TELEGRAM_C2_CREDENTIAL_PULL",
            supporting_evidence_ids=vd_evts[:10] if vd_evts else [events[0].event_id]
        )

    # Specific Loaders / Botnets
    if any(k in combined_sig for k in ["qakbot", "qbot", "regsvr32", "stager_dll"]):
        qb_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["qakbot", "qbot", "regsvr32", "rundll32"])]
        return FamilyPrediction(
            family_name="Loader.Qakbot",
            confidence=0.90,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_QAKBOT_REGSVR32_DLL_INJECTION",
            supporting_evidence_ids=qb_evts[:10] if qb_evts else [events[0].event_id]
        )

    if any(k in combined_sig for k in ["icedid", "bokbot"]):
        id_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["icedid", "bokbot", "rundll32"])]
        return FamilyPrediction(
            family_name="Loader.IcedID",
            confidence=0.89,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_ICEDID_LOADER_RUNDLL32_EXEC",
            supporting_evidence_ids=id_evts[:10] if id_evts else [events[0].event_id]
        )

    if any(k in combined_sig for k in ["mirai", "telnet_scan", "dvr_exploit", "scanner_syn"]):
        mr_evts = [e.event_id for e in events if any(k in str(e.safe_arguments).lower() for k in ["mirai", "telnet", "scanner"])]
        return FamilyPrediction(
            family_name="Botnet.Mirai",
            confidence=0.88,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_MIRAI_TELNET_FLOOD_BOTNET",
            supporting_evidence_ids=mr_evts[:10] if mr_evts else [events[0].event_id]
        )

    # Primary Rule 1: Ransomware (Default WannaCry)
    if "Ransomware/Impact" in claim_cats or "Ransomware/FileModification" in claim_cats or "vssadmin" in all_args_str or ".locked" in all_args_str or "ransom" in all_args_str:
        ransom_evts = [
            e.event_id for e in events
            if any(k in str(e.safe_arguments).lower() for k in ["vssadmin", ".locked", "ransom", "decrypt", "wncry"])
        ]
        return FamilyPrediction(
            family_name="Ransomware.WannaCry",
            confidence=0.92,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_RANSOMWARE_FILE_ENCRYPTION_VSS_DELETE",
            supporting_evidence_ids=ransom_evts[:10] if ransom_evts else [events[0].event_id]
        )

    # Primary Rule 2: Infostealer (Default RedLine)
    if "CredentialAccess" in claim_cats or "logindata" in all_args_str or "cookies" in all_args_str or "passwords.txt" in all_args_str:
        stealer_evts = [
            e.event_id for e in events
            if any(k in str(e.safe_arguments).lower() for k in ["logindata", "cookies", "passwords", "vault"]) or e.category == "network"
        ]
        return FamilyPrediction(
            family_name="Stealer.RedLine",
            confidence=0.88,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_INFOSTEALER_CREDENTIAL_ACCESS_EXFIL",
            supporting_evidence_ids=stealer_evts[:10] if stealer_evts else [events[0].event_id]
        )

    # Primary Rule 3: Coinminer (XMRig)
    if "stratum" in all_args_str or "xmrig" in all_args_str or "pool" in all_args_str or "miner" in all_args_str:
        miner_evts = [
            e.event_id for e in events
            if any(k in str(e.safe_arguments).lower() for k in ["stratum", "xmrig", "pool", "miner"]) or e.category == "service"
        ]
        return FamilyPrediction(
            family_name="Coinminer.XMRig",
            confidence=0.89,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_COINMINER_STRATUM_POOL_SERVICE",
            supporting_evidence_ids=miner_evts[:10] if miner_evts else [events[0].event_id]
        )

    # Primary Rule 4: Trojan / Backdoor (AsyncRAT)
    if "Persistence/Registry" in claim_cats or "asyncrat" in all_args_str or "autorun" in all_args_str:
        trojan_evts = [
            e.event_id for e in events
            if e.category in ["registry", "network", "process"]
        ]
        return FamilyPrediction(
            family_name="Trojan.AsyncRAT",
            confidence=0.85,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_TROJAN_REGISTRY_AUTORUN_REVERSE_C2",
            supporting_evidence_ids=trojan_evts[:10] if trojan_evts else [events[0].event_id]
        )

    # Primary Rule 5: Dropper (Emotet)
    if "Execution/Scripting" in claim_cats or "downloadstring" in all_args_str or "winword" in all_args_str:
        drop_evts = [
            e.event_id for e in events
            if any(k in str(e.safe_arguments).lower() for k in ["powershell", "download", "temp", "winword"])
        ]
        return FamilyPrediction(
            family_name="Dropper.Emotet",
            confidence=0.84,
            confidence_label="High",
            rule_triggered="FALLBACK_RULE_DROPPER_POWERSHELL_PAYLOAD_FETCH",
            supporting_evidence_ids=drop_evts[:10] if drop_evts else [events[0].event_id]
        )

    # Fallback: Benign
    benign_evts = [events[0].event_id] if events else []
    return FamilyPrediction(
        family_name="Benign.Activity",
        confidence=0.96,
        confidence_label="High",
        rule_triggered="FALLBACK_RULE_NO_SECURITY_THREAT_INDICATORS",
        supporting_evidence_ids=benign_evts
    )
