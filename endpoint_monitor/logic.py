import json

# Mock Whitelist of Safe Hooks
SAFE_HOOKS = [
    'User32.dll', 'Kernel32.dll', 'Gdi32.dll', 'ntdll.dll',
    'comctl32.dll', 'msvcrt.dll', 'ws2_32.dll'
]

def analyze_hooks(hooks_list):
    """
    Analyzes a list of active hooks/dlls.
    Returns:
    - active_risk: Boolean
    - risk_details: List of suspicious items
    """
    if not hooks_list:
        return False, []
        
    suspicious = []
    for hook in hooks_list:
        # Simple heuristic: if not in safe list (case insensitive check)
        # In reality this would be much more complex (signature verification etc)
        is_safe = False
        for safe in SAFE_HOOKS:
            if safe.lower() in hook.lower():
                is_safe = True
                break
        
        if not is_safe:
            suspicious.append(hook)
            
    return len(suspicious) > 0, suspicious
