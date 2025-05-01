from randao import Randao

class PoSC:
    def __init__(self):
        self.validators = {}
        self.randao = Randao()

    def add_validator(self, validator_id, stake):
        """Add a validator with a given stake."""
        if (self.validators[validator_id]):
            raise KeyError('Validator is already in the pool')
        #self.validators[validator_id] = (Validator(validator_id, stake))

    def remove_validator(self, validator_id):
        if (not self.validators[validator_id]):
            raise KeyError('Validator is not in the pool')
        del self.validators[validator_id]
        return

    def select_leader(self):
        """Select the next validator based on their stake and Randao randomness."""
        # Get the randomness from Randao
        randao_randomness = self.randao.get_random_value()
        
        # Normalize randomness to validator selection (0-1 range)
        rand_value = int(randao_randomness, 16) % 100

        # Weighted selection based on stake
        total_stake = sum([validator.stake for validator in self.validators])
        cumulative_stake = 0
        for validator in self.validators:
            cumulative_stake += validator.stake
            if cumulative_stake / total_stake * 100 > rand_value:
                return validator.validator_id
        
        return None  # Default fallback