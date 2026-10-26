import os
import psutil
from typing import Dict, Any, List

SUSPICIOUS_NAMES = [
    "keylogger", "backdoor", "mimikatz", "netcat", "nc.exe", "cryptominer", "xmrig",
    "meterpreter", "trojan", "ransomware", "dropper", "darkcomet"
]

HIGH_RISK_PATHS = [
    "/tmp", "/var/tmp", "/dev/shm", "C:\\Windows\\Temp", "AppData\\Local\\Temp"
]

def analyze_running_processes(limit: int = 50) -> List[Dict[str, Any]]:
    """Inspects running processes using psutil and flags suspicious activity."""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'exe', 'cmdline']):
        try:
            info = proc.info
            pid = info.get('pid')
            name = info.get('name') or f"process_{pid}"
            exe = info.get('exe') or ""
            cpu = info.get('cpu_percent') or 0.0
            mem = round(info.get('memory_percent') or 0.0, 2)
            
            # Risk heuristics
            risk_score = 0
            reasons = []
            name_lower = name.lower()
            
            # Check suspicious process names
            for sus in SUSPICIOUS_NAMES:
                if sus in name_lower:
                    risk_score += 65
                    reasons.append(f"Suspicious binary name matches '{sus}'")
            
            # Check execution from temp / shared memory
            if exe:
                for temp_path in HIGH_RISK_PATHS:
                    if temp_path.lower() in exe.lower():
                        risk_score += 35
                        reasons.append(f"Executing from temporary directory: {exe}")
                        break
            
            # High resource consumption / potential mining
            if cpu > 80.0:
                risk_score += 25
                reasons.append("Anomalous sustained CPU consumption (>80%)")
            if mem > 40.0:
                risk_score += 15
                reasons.append("Unusual high memory footprint (>40%)")
            
            risk_score = min(100, risk_score)
            risk_level = "low"
            if risk_score >= 70:
                risk_level = "critical"
            elif risk_score >= 40:
                risk_level = "high"
            elif risk_score >= 20:
                risk_level = "moderate"
            
            processes.append({
                "pid": pid,
                "name": name,
                "user": info.get('username') or "system",
                "cpu_percent": cpu,
                "memory_percent": mem,
                "status": info.get('status') or "running",
                "executable": exe,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "is_suspicious": risk_score >= 40,
                "reasons": reasons,
            })
            
            if len(processes) >= limit:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    # Sort by risk score descending, then cpu descending
    processes.sort(key=lambda p: (p["risk_score"], p["cpu_percent"]), reverse=True)
    return processes

def terminate_process(pid: int) -> Dict[str, Any]:
    """Safely terminates a targeted process by PID."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        # Protect system init / PID 1
        if pid <= 1:
            return {"success": False, "error": "Cannot terminate critical system init process."}
        proc.terminate()
        proc.wait(timeout=3)
        return {"success": True, "pid": pid, "name": name, "message": f"Process {name} (PID {pid}) terminated."}
    except psutil.TimeoutExpired:
        try:
            proc.kill()
            return {"success": True, "pid": pid, "message": f"Process forcefully killed."}
        except Exception as e:
            return {"success": False, "error": str(e)}
    except psutil.NoSuchProcess:
        return {"success": False, "error": f"Process with PID {pid} does not exist."}
    except psutil.AccessDenied:
        return {"success": False, "error": f"Permission denied to terminate PID {pid}. Elevated privileges required."}
    except Exception as e:
        return {"success": False, "error": str(e)}

def isolate_process(pid: int) -> Dict[str, Any]:
    """Suspends a process to prevent malicious behavior without terminating."""
    try:
        if pid <= 1:
            return {"success": False, "error": "Cannot suspend critical system init process."}
        proc = psutil.Process(pid)
        proc.suspend()
        return {"success": True, "pid": pid, "message": f"Process {proc.name()} (PID {pid}) suspended and isolated."}
    except Exception as e:
        return {"success": False, "error": str(e)}
