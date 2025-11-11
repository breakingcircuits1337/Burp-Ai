# -*- coding: utf-8 -*-
# Atlas AI Extension - Main Extension Class

from burp import IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation, IMessageEditorTabFactory, IScanIssue, IScannerListener
from java.awt import BorderLayout, Font, Color
from java.awt.event import ActionListener
from javax.swing import (
    JPanel, JLabel, JTabbedPane, JOptionPane, BorderFactory, 
    BoxLayout, Box, SwingUtilities
)
from java.util import ArrayList
from javax.swing import JMenuItem
from java.io import PrintWriter, InputStreamReader, BufferedReader
from java.lang import Runtime
import json
import threading
import time

from atlas_ui import AtlasUIBuilder
from atlas_tab import AtlasAITab
from atlas_scanner_tab import AtlasScannerTab
from atlas_scanner_findings_tab import AtlasScannerFindingsTab
from atlas_adapters import OpenAIAdapter, GeminiAdapter, MistralAdapter, GroqAdapter, LocalLLMAdapter
from atlas_config import AtlasConfig
from atlas_recon import ReconManager
from atlas_scenario import ScenarioManager

class AtlasAIExtension(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory, IScannerListener):
    """Main Atlas AI Extension class."""
    
    def registerExtenderCallbacks(self, callbacks):
        """Register extension with Burp Suite."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        callbacks.setExtensionName("Atlas AI Pro")
        self._stdout.println("[Atlas AI] Initializing extension...")
        
        self._config = AtlasConfig(callbacks)
        self._scenario_manager = ScenarioManager(self)
        self._current_adapter = None
        self._ui_builder = AtlasUIBuilder(self)
        self._recon_manager = ReconManager(self)
        self._response_cache = {}
        self._cache_lock = threading.Lock()
        self._max_cache_size = 100
        self._pending_selection_analysis = None
        self._pending_analysis_request = None
        self._pending_exploitation_request = None
        self._scanner_findings_tab = None
        
        self._create_ui()
        self._init_adapter()
        
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerScannerListener(self)
        
        self._stdout.println("[Atlas AI] Extension loaded successfully!")
        self._log_to_ui("Welcome to Atlas AI Pro! Create or select a scenario to begin.")
    
    def getTabCaption(self):
        return "Atlas AI"
    
    def getUiComponent(self):
        return self._main_panel

    def createNewInstance(self, controller, editable):
        return AtlasAITab(self, controller, editable)

    def createMenuItems(self, invocation):
        """Create context menu items."""
        menu_items = ArrayList()
        context = invocation.getInvocationContext()
        
        # HTTP message contexts
        if context in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY
        ]:
            req_item = JMenuItem("Atlas AI: Analyze Request")
            req_item.addActionListener(lambda e: self.analyze_in_tab(invocation, "request"))
            menu_items.add(req_item)

            resp_item = JMenuItem("Atlas AI: Analyze Response")
            resp_item.addActionListener(lambda e: self.analyze_in_tab(invocation, "response"))
            menu_items.add(resp_item)

            explain_item = JMenuItem("Atlas AI: Explain Selection")
            explain_item.addActionListener(lambda e: self.explain_selection(invocation))
            menu_items.add(explain_item)

            payload_item = JMenuItem("Atlas AI: Generate Attack Vectors")
            payload_item.addActionListener(lambda e: self.analyze_in_tab(invocation, "payloads"))
            menu_items.add(payload_item)
        
        # Scanner results context
        if context == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS:
            issues = invocation.getSelectedIssues()
            if issues and len(issues) > 0:
                scanner_item = JMenuItem("Atlas AI: Analyze & Explain Finding")
                scanner_item.addActionListener(lambda e: self.analyze_scanner_finding(invocation))
                menu_items.add(scanner_item)
                
                exploit_item = JMenuItem("Atlas AI: Suggest Exploitation")
                exploit_item.addActionListener(lambda e: self.suggest_exploitation(invocation))
                menu_items.add(exploit_item)
        
        return menu_items

    def _create_ui(self):
        self._main_panel = JPanel(BorderLayout())
        
        # Main Header
        header = self._create_header()
        
        # Scenario Control Panel
        scenario_panel = self._ui_builder.create_scenario_control_panel()
        
        # Combined Header Panel
        top_panel = JPanel(BorderLayout())
        top_panel.add(header, BorderLayout.NORTH)
        top_panel.add(scenario_panel, BorderLayout.SOUTH)
        
        self._main_panel.add(top_panel, BorderLayout.NORTH)
        
        # Tabbed Pane
        self._tabbed_pane = JTabbedPane()
        self._config_panel = self._ui_builder.create_config_panel()
        self._tabbed_pane.addTab("Atlas AI Config", self._config_panel)
        
        self._analysis_panel = self._ui_builder.create_enhanced_analysis_panel()
        self._tabbed_pane.addTab("Atlas AI Analysis", self._analysis_panel)

        self._recon_panel = self._ui_builder.create_recon_panel()
        self._tabbed_pane.addTab("Recon", self._recon_panel)
        
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)

    def _create_header(self):
        header = JPanel()
        header.setLayout(BoxLayout(header, BoxLayout.X_AXIS))
        header.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        title = JLabel("Atlas AI Pro - Advanced Security Analysis")
        title.setFont(Font("Arial", Font.BOLD, 20))
        header.add(title)
        
        header.add(Box.createHorizontalGlue())
        
        self._status_label = JLabel("Not Configured")
        self._status_label.setForeground(Color.RED)
        self._status_label.setFont(Font("Arial", Font.PLAIN, 14))
        header.add(self._status_label)
        
        return header

    def _init_adapter(self):
        """Initialize the AI adapter based on saved configuration."""
        config_data = self._config.get_all()
        backend = config_data.get("backend", "openai")
        
        adapter_map = {
            "openai": (OpenAIAdapter, "api_key", "model"),
            "gemini": (GeminiAdapter, "gemini_api_key", "gemini_model"),
            "mistral": (MistralAdapter, "mistral_api_key", "mistral_model"),
            "groq": (GroqAdapter, "groq_api_key", "groq_model"),
        }

        if backend in adapter_map:
            AdapterClass, api_key_name, model_name = adapter_map[backend]
            api_key = config_data.get(api_key_name)
            model = config_data.get(model_name)
            
            if api_key and model:
                self._current_adapter = AdapterClass(
                    api_key,
                    model,
                    timeout=config_data.get("timeout", 60)
                )
                self._current_adapter.set_burp_callbacks(self._callbacks)
                self._update_status("Connected to " + backend.title(), Color.GREEN)
            else:
                self._current_adapter = None
                self._update_status("Not Configured", Color.RED)

        elif backend == "local":
            local_url = config_data.get("local_url")
            if local_url:
                self._current_adapter = LocalLLMAdapter(
                    local_url,
                    config_data.get("model", "local-model"),
                    timeout=config_data.get("timeout", 60),
                    api_key=config_data.get("local_api_key"),
                    config=config_data
                )
                self._current_adapter.set_burp_callbacks(self._callbacks)
                self._update_status("Connected to Local LLM", Color.GREEN)
            else:
                self._current_adapter = None
                self._update_status("Not Configured", Color.RED)
        else:
            self._current_adapter = None
            self._update_status("Not Configured", Color.RED)
    
    def save_settings(self, settings):
        """Save settings and reinitialize adapter."""
        self._config.update(settings)
        self._init_adapter()
        
        if self._current_adapter:
            self._log_to_ui("Settings saved! AI analysis ready.")
        else:
            self._log_to_ui("Please configure your AI backend.")
    
    def test_connection(self):
        """Test the AI connection."""
        # Save settings before testing
        self._ui_builder.save_settings() 
        
        if not self._current_adapter:
            JOptionPane.showMessageDialog(self._main_panel,
                "Please configure and save your settings first",
                "No Configuration",
                JOptionPane.WARNING_MESSAGE)
            return
        
        self._log_to_ui("Testing connection to " + self._config.get("backend").title() + "...")
        
        def test():
            try:
                from atlas_prompts import AtlasPrompts
                response = self._current_adapter.send_message(AtlasPrompts.CONNECTION_TEST)
                SwingUtilities.invokeLater(lambda: self._log_to_ui("SUCCESS: " + response))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self._log_to_ui("ERROR: Connection failed - " + str(e)))
        
        thread = threading.Thread(target=test)
        thread.daemon = True
        thread.start()

    def analyze_message(self, request_bytes, response_bytes, service, analysis_type="request"):
        """Analyze HTTP message and return result."""
        if not self._current_adapter:
            return "Atlas AI not configured. Please configure API settings."
        
        try:
            import hashlib
            cache_content = str(request_bytes) + str(response_bytes) + analysis_type
            cache_key = hashlib.sha256(cache_content.encode('utf-8')).hexdigest()
            
            if analysis_type != "payloads":
                with self._cache_lock:
                    if cache_key in self._response_cache:
                        return self._response_cache[cache_key]
            
            analysis = self._build_http_analysis(request_bytes, response_bytes, service)
            prompt = self._get_analysis_prompt(analysis_type)
            
            if analysis_type == "payloads" and "{http_context}" in prompt:
                formatted_prompt = prompt.format(http_context=analysis)
                ai_response = self._current_adapter.send_message(formatted_prompt)
            else:
                ai_response = self._current_adapter.send_message(prompt + "\n\n" + analysis)
            
            result = self._format_analysis_result(ai_response, service, analysis_type)
            
            if analysis_type != "payloads":
                with self._cache_lock:
                    self._response_cache[cache_key] = result
                    if len(self._response_cache) > self._max_cache_size:
                        oldest_key = next(iter(self._response_cache))
                        del self._response_cache[oldest_key]
            
            # Add to active scenario
            active_scenario = self.get_scenario_manager().get_active_scenario()
            if active_scenario:
                active_scenario.add_finding(result)

            return result
            
        except Exception as e:
            self._stderr.println("[Atlas AI] Analysis error: " + str(e))
            return "Error during analysis: " + str(e)

    def _build_http_analysis(self, request_bytes, response_bytes, service):
        """Build HTTP analysis text."""
        analysis = ""
        if request_bytes:
            req_info = self._helpers.analyzeRequest(service, request_bytes)
            analysis += "=== REQUEST ===\n"
            analysis += "URL: " + str(req_info.getUrl()) + "\n"
            analysis += "Method: " + req_info.getMethod() + "\n\nHeaders:\n"
            for header in req_info.getHeaders():
                analysis += header + "\n"
            body_offset = req_info.getBodyOffset()
            if body_offset < len(request_bytes):
                body = self._helpers.bytesToString(request_bytes[body_offset:])
                analysis += "\nBody:\n" + body[:3000]
        
        if response_bytes:
            resp_info = self._helpers.analyzeResponse(response_bytes)
            analysis += "\n=== RESPONSE ===\n"
            analysis += "Status: " + str(resp_info.getStatusCode()) + "\n\nHeaders:\n"
            for header in resp_info.getHeaders():
                analysis += header + "\n"
            body_offset = resp_info.getBodyOffset()
            if body_offset < len(response_bytes):
                body = self._helpers.bytesToString(response_bytes[body_offset:])
                analysis += "\nBody:\n" + body[:3000]

        return analysis

    def _get_analysis_prompt(self, analysis_type):
        from atlas_prompts import AtlasPrompts
        return {
            "request": AtlasPrompts.REQUEST_ANALYSIS,
            "response": AtlasPrompts.RESPONSE_ANALYSIS,
            "payloads": AtlasPrompts.PAYLOAD_GENERATION,
            "explain": AtlasPrompts.SELECTION_EXPLANATION
        }.get(analysis_type, AtlasPrompts.REQUEST_ANALYSIS)

    def _format_analysis_result(self, ai_response, service, analysis_type):
        url = str(service.getProtocol()) + "://" + str(service.getHost()) if service else "Unknown"
        result = "ATLAS AI SECURITY ANALYSIS\n" + "=" * 60 + "\n"
        result += "Target: " + url + "\n"
        result += "Analysis Type: " + analysis_type.title() + "\n"
        result += "Time: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n"
        result += "=" * 60 + "\n\n"
        result += ai_response
        return result

    def analyze_in_tab(self, invocation, analysis_type):
        self._stdout.println("[Atlas AI] Analysis requested: " + analysis_type)
        messages = invocation.getSelectedMessages()
        if not messages: return
        
        message = messages[0]
        self._pending_analysis_request = {
            'type': analysis_type,
            'request': message.getRequest(),
            'response': message.getResponse(),
            'service': message.getHttpService()
        }
        
        def perform_analysis():
            try:
                result = self.analyze_message(
                    message.getRequest(), message.getResponse(), message.getHttpService(), analysis_type
                )
                SwingUtilities.invokeLater(lambda: self._ui_builder.show_in_analysis_panel(result))
                SwingUtilities.invokeLater(lambda: self._tabbed_pane.setSelectedIndex(1))
            except Exception as e:
                self._stderr.println("[Atlas AI] Error in analyze_in_tab: " + str(e))
        
        thread = threading.Thread(target=perform_analysis)
        thread.daemon = True
        thread.start()
        self._log_to_ui("Analysis in progress. Check the Atlas AI Analysis tab.")

    def explain_selection(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return
        
        bounds = invocation.getSelectionBounds()
        if not bounds: return

        message = messages[0]
        context = invocation.getInvocationContext()
        content = message.getRequest() if context in [IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST, IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST] else message.getResponse()
        selected_text = self._helpers.bytesToString(content[bounds[0]:bounds[1]])

        self._pending_selection_analysis = selected_text
        
        def analyze_selection():
            try:
                prompt = "Explain this selected text from a security perspective:\n\n" + selected_text
                response = self._current_adapter.send_message(prompt)
                result = "SELECTION ANALYSIS\n" + "=" * 60 + "\n\n"
                result += "Selected Text:\n" + selected_text[:500] + "\n\n" + "=" * 60 + "\n\n" + response
                SwingUtilities.invokeLater(lambda: self._ui_builder.show_in_analysis_panel(result))
                SwingUtilities.invokeLater(lambda: self._tabbed_pane.setSelectedIndex(1))
            except Exception as e:
                self._stderr.println("[Atlas AI] Selection analysis error: " + str(e))
        
        thread = threading.Thread(target=analyze_selection)
        thread.daemon = True
        thread.start()
        self._log_to_ui("Selection analysis in progress. Check the Atlas AI Analysis tab.")

    def analyze_scanner_finding(self, invocation):
        issues = invocation.getSelectedIssues()
        if not issues: return
        if not self._current_adapter: 
            self._log_to_ui("Atlas AI not configured.")
            return

        self._ui_builder.analyze_scanner_finding_in_tab(issues[0], "analysis")
        self._tabbed_pane.setSelectedIndex(1)
        self._log_to_ui("Scanner finding analysis in progress...")

    def suggest_exploitation(self, invocation):
        issues = invocation.getSelectedIssues()
        if not issues: return
        if not self._current_adapter: 
            self._log_to_ui("Atlas AI not configured.")
            return

        self._ui_builder.analyze_scanner_finding_in_tab(issues[0], "exploitation")
        self._tabbed_pane.setSelectedIndex(1)
        self._log_to_ui("Exploitation analysis in progress...")

    def _build_scanner_issue_text(self, issue):
        text = "Issue: " + issue.getIssueName() + "\n"
        text += "URL: " + str(issue.getUrl()) + "\n"
        text += "Severity: " + issue.getSeverity() + "\n"
        text += "Confidence: " + issue.getConfidence() + "\n\n"
        if issue.getIssueDetail(): text += "Details:\n" + issue.getIssueDetail()[:1000] + "\n\n"
        if issue.getIssueBackground(): text += "Background:\n" + issue.getIssueBackground()[:500] + "\n\n"
        if issue.getRemediationDetail(): text += "Remediation:\n" + issue.getRemediationDetail()[:500]
        return text

    def send_chat_message(self, message):
        active_scenario = self._scenario_manager.get_active_scenario()
        if not active_scenario:
            self._log_to_ui("No active scenario. Please create one first.")
            return

        if not self._current_adapter: 
            self._log_to_ui("Please configure your AI settings first")
            return

        # Add user message to history and UI
        active_scenario.add_chat_message("You", message)
        self._ui_builder.append_to_chat("You: " + message + "\n\n")

        # Prepare context-aware prompt
        from atlas_prompts import AtlasPrompts
        context_prompt = AtlasPrompts.CONTEXTUAL_CHAT.format(
            chat_history=active_scenario.get_full_chat_history(),
            recon_results=active_scenario.recon_results,
            findings="\n".join(active_scenario.findings)
        )
        final_prompt = context_prompt + "\n\n" + message

        def send():
            try:
                response = self._current_adapter.send_message(final_prompt)
                # Add AI response to history and UI
                active_scenario.add_chat_message("Atlas AI", response)
                SwingUtilities.invokeLater(lambda: self._ui_builder.append_to_chat("Atlas AI: " + response + "\n\n" + "-" * 80 + "\n\n"))
            except Exception as e:
                error_msg = "ERROR: " + str(e)
                active_scenario.add_chat_message("System", error_msg)
                SwingUtilities.invokeLater(lambda: self._ui_builder.append_to_chat(error_msg + "\n\n"))
        
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()

    def start_reconnaissance(self, target):
        """Start a reconnaissance scan and store results in the active scenario."""
        active_scenario = self._scenario_manager.get_active_scenario()
        if not active_scenario:
            self._log_to_ui("No active scenario. Please create one first.")
            return
        
        self._recon_manager.start_recon(target)

    def summarize_recon_results(self, results):
        """Summarize reconnaissance results using AI and store in the active scenario."""
        active_scenario = self._scenario_manager.get_active_scenario()
        if not active_scenario:
            self._log_to_ui("No active scenario. Please create one first.")
            return

        if not self._current_adapter:
            self._log_to_ui("Please configure your AI backend first.")
            return

        self._log_to_ui("Summarizing reconnaissance results for scenario: {}".format(active_scenario.name))
        active_scenario.set_recon_results(results)

        def summarize():
            try:
                from atlas_prompts import AtlasPrompts
                prompt = AtlasPrompts.RECON_SUMMARY + "\n\n" + results
                response = self._current_adapter.send_message(prompt)
                summary_text = "\n\n--- AI SUMMARY ---\n" + response
                active_scenario.add_chat_message("System", "Recon Summary: " + response)
                SwingUtilities.invokeLater(lambda: self._ui_builder.recon_output_area.append(summary_text))
            except Exception as e:
                error_text = "\n\n--- ERROR SUMMARIZING ---\n" + str(e)
                SwingUtilities.invokeLater(lambda: self._ui_builder.recon_output_area.append(error_text))

        thread = threading.Thread(target=summarize)
        thread.daemon = True
        thread.start()

    def run_terminal_command(self, command):
        """Runs a terminal command and streams the output to the recon UI."""
        def stream_output():
            try:
                process = Runtime.getRuntime().exec(command)
                
                stdout_reader = BufferedReader(InputStreamReader(process.getInputStream()))
                stderr_reader = BufferedReader(InputStreamReader(process.getErrorStream()))

                line = stdout_reader.readLine()
                while line is not None:
                    final_line = line + "\n"
                    SwingUtilities.invokeLater(lambda: self._ui_builder.recon_output_area.append(final_line))
                    line = stdout_reader.readLine()

                line = stderr_reader.readLine()
                while line is not None:
                    final_line = "[ERROR] " + line + "\n"
                    SwingUtilities.invokeLater(lambda: self._ui_builder.recon_output_area.append(final_line))
                    line = stderr_reader.readLine()

                process.waitFor()
                stdout_reader.close()
                stderr_reader.close()

            except Exception as e:
                final_error = "[FATAL] Error executing command: " + str(e) + "\n"
                SwingUtilities.invokeLater(lambda: self._ui_builder.recon_output_area.append(final_error))

        thread = threading.Thread(target=stream_output)
        thread.daemon = True
        thread.start()

    def _log_to_ui(self, message):
        active_scenario = self._scenario_manager.get_active_scenario()
        if active_scenario:
            active_scenario.add_chat_message("System", message)
        
        timestamp = time.strftime("%H:%M:%S")
        self._ui_builder.append_to_chat("[" + timestamp + "] " + message + "\n")
    
    def _update_status(self, status, color):
        self._status_label.setText(status)
        self._status_label.setForeground(color)

    def newScanIssue(self, issue):
        active_scenario = self._scenario_manager.get_active_scenario()
        if active_scenario:
            active_scenario.add_finding(self._build_scanner_issue_text(issue))
        if self._scanner_findings_tab:
            self._scanner_findings_tab.add_scanner_finding(issue)
    
    def get_config(self): return self._config
    def get_helpers(self): return self._helpers
    def get_stdout(self): return self._stdout
    def get_stderr(self): return self._stderr
    def get_scenario_manager(self): return self._scenario_manager
    def get_ui_builder(self): return self._ui_builder
    def get_current_adapter(self): return self._current_adapter
    def get_pending_selection_analysis(self):
        analysis = self._pending_selection_analysis
        self._pending_selection_analysis = None
        return analysis
    def get_pending_analysis_request(self):
        request = self._pending_analysis_request
        self._pending_analysis_request = None
        return request
    def clear_response_cache(self):
        self._response_cache = {}
        self._log_to_ui("Response cache cleared.")
