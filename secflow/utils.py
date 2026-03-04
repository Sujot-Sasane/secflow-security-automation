import shutil
import subprocess
from typing import List, Tuple, Optional

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(args: List[str], timeout: int = 600) -> Tuple[int, str, str]:
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return 124, out, err
