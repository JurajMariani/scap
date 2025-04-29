import hashlib
import random
import time

class Randao:
    def __init__(self):
        self.commitments = {}
        self.reveals = {}
        self.stale = False

    def commit(self, validator_id, commit_value):
        """Validators commit to a secret value"""
        self.commitments[validator_id] = commit_value

    def reveal(self, validator_id, secret_value):
        """Validators reveal their secret value after committing"""
        if validator_id not in self.commitments:
            raise ValueError(f"Validator {validator_id} has not committed yet.")
        
        commit_value = self.commitments[validator_id]
        self.stale = False
        
        # Reveal phase
        if hashlib.sha256(secret_value.encode()).hexdigest() == commit_value:
            self.reveals[validator_id] = secret_value
        else:
            raise ValueError(f"Revealed value does not match the commitment for {validator_id}.")
        
    def commit_and_reveal(self, validator_id, secret_value):
        """Simulate the commit and reveal phases of Randao."""
        self.commit(validator_id, hashlib.sha256(secret_value.encode()).hexdigest())
        self.reveal(validator_id, secret_value)
        
    def get_random_value(self):
        """Generate randomness from the reveals"""
        if (self.stale):
            raise ValueError('Random value is stale.')
        combined_reveals = ''.join([self.reveals[v] for v in self.reveals])
        if not combined_reveals:
            raise ValueError("No reveals have been made yet.")
        self.stale = True
        # Wipe commits and reveals
        self.commitments = {}
        self.reveals = {}
        # Hash the combined reveals to create randomness
        return hashlib.sha256(combined_reveals.encode()).hexdigest()
