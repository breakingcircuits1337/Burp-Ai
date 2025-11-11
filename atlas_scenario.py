# -*- coding: utf-8 -*-
# Atlas AI Attack Scenario Manager

import json
import time

class AttackScenario:
    """Represents a single, stateful attack scenario."""
    def __init__(self, name):
        self.name = name
        self.creation_time = time.time()
        self.chat_history = []
        self.recon_results = ""
        self.findings = []

    def add_chat_message(self, role, content):
        """Adds a message to the scenario's chat history."""
        self.chat_history.append({"role": role, "content": content, "timestamp": time.time()})

    def get_full_chat_history(self):
        """Returns the complete chat history as a single string."""
        return "\n".join(["{}: {}".format(msg['role'], msg['content']) for msg in self.chat_history])

    def set_recon_results(self, results):
        """Stores the results of a reconnaissance scan."""
        self.recon_results = results

    def add_finding(self, finding):
        """Adds a discovered vulnerability or finding to the scenario."""
        self.findings.append(finding)

    def to_dict(self):
        """Serializes the scenario object to a dictionary."""
        return {
            "name": self.name,
            "creation_time": self.creation_time,
            "chat_history": self.chat_history,
            "recon_results": self.recon_results,
            "findings": [str(f) for f in self.findings] # Store findings as strings
        }

    @classmethod
    def from_dict(cls, data):
        """Deserializes a dictionary into a scenario object."""
        scenario = cls(data['name'])
        scenario.creation_time = data.get('creation_time', time.time())
        scenario.chat_history = data.get('chat_history', [])
        scenario.recon_results = data.get('recon_results', "")
        scenario.findings = data.get('findings', [])
        return scenario

class ScenarioManager:
    """Manages the lifecycle of all attack scenarios."""
    def __init__(self, extension):
        self.extension = extension
        self.scenarios = {}
        self.active_scenario_name = None
        self.load_scenarios()

    def create_scenario(self, name):
        """Creates a new, empty attack scenario."""
        if name in self.scenarios:
            raise ValueError("Scenario with this name already exists.")
        scenario = AttackScenario(name)
        self.scenarios[name] = scenario
        self.set_active_scenario(name)
        self.save_scenarios()
        return scenario

    def set_active_scenario(self, name):
        """Sets the currently active scenario."""
        if name not in self.scenarios:
            raise ValueError("Scenario not found.")
        self.active_scenario_name = name
        self.extension._log_to_ui("Active scenario set to: {}".format(name))

    def get_active_scenario(self):
        """Returns the currently active AttackScenario object."""
        if not self.active_scenario_name:
            # If no active scenario, create a default one
            if not self.scenarios:
                self.create_scenario("Default Scenario")
            else:
                # Or, set the first available one as active
                self.set_active_scenario(self.scenarios.keys()[0])
        
        return self.scenarios.get(self.active_scenario_name)

    def get_scenario_names(self):
        """Returns a list of all scenario names."""
        return self.scenarios.keys()

    def save_scenarios(self):
        """Saves all scenarios to Burp's persistent storage."""
        try:
            serialized_scenarios = {name: scenario.to_dict() for name, scenario in self.scenarios.items()}
            self.extension.get_config().set("scenarios", json.dumps(serialized_scenarios))
            self.extension._log_to_ui("All scenarios saved.")
        except Exception as e:
            self.extension.get_stderr().println("[Atlas AI] Error saving scenarios: " + str(e))

    def load_scenarios(self):
        """Loads all scenarios from Burp's persistent storage."""
        try:
            scenarios_json = self.extension.get_config().get("scenarios")
            if scenarios_json:
                serialized_scenarios = json.loads(scenarios_json)
                self.scenarios = {name: AttackScenario.from_dict(data) for name, data in serialized_scenarios.items()}
                self.extension.get_stdout().println("[Atlas AI] Loaded {} scenarios.".format(len(self.scenarios)))
                
                # Set a default active scenario if none is set
                if not self.active_scenario_name and self.scenarios:
                    self.active_scenario_name = self.scenarios.keys()[0]
            else:
                self.extension.get_stdout().println("[Atlas AI] No scenarios found to load.")
        except Exception as e:
            self.extension.get_stderr().println("[Atlas AI] Error loading scenarios: " + str(e))
