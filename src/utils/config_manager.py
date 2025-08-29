"""
Configuration Manager for Deadbolt Defender
Handles dynamic configuration updates and persistence
"""

import os
import json
from datetime import datetime
import config
from logger import log_event

class ConfigManager:
    """Manages dynamic configuration updates for Deadbolt Defender"""
    
    def __init__(self):
        self.config_file = "deadbolt_config.json"
        self.load_config()
    
    def load_config(self):
        """Load configuration from file if it exists"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    saved_config = json.load(f)
                
                # Update module config with saved values
                if 'TARGET_DIRS' in saved_config:
                    config.TARGET_DIRS[:] = saved_config['TARGET_DIRS']
                
                if 'RULES' in saved_config:
                    config.RULES.update(saved_config['RULES'])
                
                if 'ACTIONS' in saved_config:
                    config.ACTIONS.update(saved_config['ACTIONS'])
                
                log_event("INFO", f"Configuration loaded from {self.config_file}")
                
            except Exception as e:
                log_event("ERROR", f"Failed to load configuration: {e}")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            config_data = {
                'TARGET_DIRS': config.TARGET_DIRS,
                'RULES': config.RULES,
                'ACTIONS': config.ACTIONS,
                'saved_at': str(datetime.now())
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            log_event("INFO", f"Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            log_event("ERROR", f"Failed to save configuration: {e}")
            return False
    
    def update_target_dirs(self, new_dirs):
        """Update target directories"""
        config.TARGET_DIRS[:] = new_dirs
        log_event("INFO", f"Updated target directories: {new_dirs}")
        return self.save_config()
    
    def update_rules(self, mass_delete_count, mass_delete_interval, mass_rename_count, mass_rename_interval):
        """Update detection rules"""
        config.RULES['mass_delete']['count'] = mass_delete_count
        config.RULES['mass_delete']['interval'] = mass_delete_interval
        config.RULES['mass_rename']['count'] = mass_rename_count
        config.RULES['mass_rename']['interval'] = mass_rename_interval
        
        log_event("INFO", f"Updated detection rules: {config.RULES}")
        return self.save_config()
    
    def update_actions(self, log_only, kill_process, shutdown, dry_run):
        """Update response actions"""
        config.ACTIONS['log_only'] = log_only
        config.ACTIONS['kill_process'] = kill_process
        config.ACTIONS['shutdown'] = shutdown
        config.ACTIONS['dry_run'] = dry_run
        
        log_event("INFO", f"Updated response actions: {config.ACTIONS}")
        return self.save_config()
    
    def get_current_config(self):
        """Get current configuration as dictionary"""
        return {
            'TARGET_DIRS': config.TARGET_DIRS.copy(),
            'RULES': config.RULES.copy(),
            'ACTIONS': config.ACTIONS.copy()
        }

# Global config manager instance
config_manager = ConfigManager()