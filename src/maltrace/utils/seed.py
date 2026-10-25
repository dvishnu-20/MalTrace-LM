import os
import random


def set_seed(seed: int = 42) -> None:
    """
    Set deterministic seed for random number generators.
    """
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)

    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:
        pass
