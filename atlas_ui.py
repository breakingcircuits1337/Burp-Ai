# -*- coding: utf-8 -*-
# Atlas AI UI Builder

from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyAdapter, KeyEvent
from javax.swing import (
    JPanel, JLabel, JButton, JTextArea, JScrollPane,
    JTextField, JPasswordField, BorderFactory, JComboBox,
    JSplitPane, Box, BoxLayout, SwingUtilities, JTabbedPane, JOptionPane,
    JCheckBox
)
import threading

class AtlasUIBuilder:
    """Handles UI creation for Atlas AI extension."""
    
    def __init__(self, extension):
        self.extension = extension
        self.chat_area = None
        self.analysis_area = None
        self.input_area = None
        self.recon_output_area = None
        self.scenario_combo = None
        self.actionable_command_panel = None
        self.command_field = None
        
        # UI components that need to be accessible
        self.backend_combo = None
        self.api_key_field = None
        self.gemini_api_key_field = None
        self.gemini_use_vision_checkbox = None
        self.mistral_api_key_field = None
        self.groq_api_key_field = None
        self.local_url_field = None
        self.local_api_key_field = None
        self.model_field = None
        self.timeout_field = None
        self.api_key_label = None
        self.gemini_api_key_label = None
        self.mistral_api_key_label = None
        self.groq_api_key_label = None
        self.local_url_label = None
        self.local_api_key_label = None
        
        # Scanner analysis components
        self.scanner_analysis_area = None
        self.analysis_tabbed_pane = None

    def create_scenario_control_panel(self):
        """Creates the panel for creating and selecting scenarios."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Attack Scenario Control"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ))

        panel.add(JLabel("Active Scenario:"))
        panel.add(Box.createHorizontalStrut(5))

        self.scenario_combo = JComboBox()
        self.update_scenario_list()
        panel.add(self.scenario_combo)

        panel.add(Box.createHorizontalStrut(10))

        new_scenario_button = JButton("New Scenario")
        panel.add(new_scenario_button)

        class ScenarioSelectAction(ActionListener):
            def __init__(self, extension, combo):
                self.extension = extension
                self.combo = combo

            def actionPerformed(self, event):
                selected = self.combo.getSelectedItem()
                if selected:
                    self.extension.get_scenario_manager().set_active_scenario(str(selected))

        self.scenario_combo.addActionListener(ScenarioSelectAction(self.extension, self.scenario_combo))

        class NewScenarioAction(ActionListener):
            def __init__(self, extension):
                self.extension = extension

            def actionPerformed(self, event):
                name = JOptionPane.showInputDialog(self.extension.getUiComponent(), "Enter new scenario name:")
                if name and name.strip():
                    try:
                        self.extension.get_scenario_manager().create_scenario(name.strip())
                        self.extension.get_ui_builder().update_scenario_list()
                    except ValueError as e:
                        JOptionPane.showMessageDialog(self.extension.getUiComponent(), str(e), "Error", JOptionPane.ERROR_MESSAGE)

        new_scenario_button.addActionListener(NewScenarioAction(self.extension))

        return panel

    def update_scenario_list(self):
        if self.scenario_combo is not None:
            listeners = self.scenario_combo.getActionListeners()
            for listener in listeners:
                self.scenario_combo.removeActionListener(listener)

            self.scenario_combo.removeAllItems()
            scenarios = self.extension.get_scenario_manager().get_scenario_names()
            for name in scenarios:
                self.scenario_combo.addItem(name)
            
            active_scenario = self.extension.get_scenario_manager().get_active_scenario()
            if active_scenario:
                self.scenario_combo.setSelectedItem(active_scenario.name)

            if listeners:
                self.scenario_combo.addActionListener(listeners[0])

    def create_settings_panel(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        row = 0
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.anchor = GridBagConstraints.CENTER
        title = JLabel("AI Backend Configuration")
        title.setFont(Font("Arial", Font.BOLD, 18))
        panel.add(title, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 1
        gbc.anchor = GridBagConstraints.WEST
        panel.add(JLabel("Backend:"), gbc)
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.backend_combo = JComboBox(["OpenAI", "Gemini", "Mistral", "Groq", "Local LLM"])
        config_data = self.extension.get_config().get_all()
        backend_map = {"openai": "OpenAI", "gemini": "Gemini", "mistral": "Mistral", "groq": "Groq", "local": "Local LLM"}
        self.backend_combo.setSelectedItem(backend_map.get(config_data.get("backend"), "OpenAI"))
        
        class BackendAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.update_backend_fields()
        
        self.backend_combo.addActionListener(BackendAction(self))
        panel.add(self.backend_combo, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.api_key_label = JLabel("OpenAI API Key:")
        panel.add(self.api_key_label, gbc)
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.api_key_field = JPasswordField(30)
        self.api_key_field.setText(config_data.get("api_key", ""))
        panel.add(self.api_key_field, gbc)
        self.gemini_api_key_label = JLabel("Gemini API Key:")
        panel.add(self.gemini_api_key_label, gbc)
        self.gemini_api_key_field = JPasswordField(30)
        self.gemini_api_key_field.setText(config_data.get("gemini_api_key", ""))
        panel.add(self.gemini_api_key_field, gbc)
        self.gemini_use_vision_checkbox = JCheckBox("Use Vision")
        self.gemini_use_vision_checkbox.setSelected(config_data.get("gemini_use_vision", False))
        panel.add(self.gemini_use_vision_checkbox, gbc)
        self.mistral_api_key_label = JLabel("Mistral API Key:")
        panel.add(self.mistral_api_key_label, gbc)
        self.mistral_api_key_field = JPasswordField(30)
        self.mistral_api_key_field.setText(config_data.get("mistral_api_key", ""))
        panel.add(self.mistral_api_key_field, gbc)
        self.groq_api_key_label = JLabel("Groq API Key:")
        panel.add(self.groq_api_key_label, gbc)
        self.groq_api_key_field = JPasswordField(30)
        self.groq_api_key_field.setText(config_data.get("groq_api_key", ""))
        panel.add(self.groq_api_key_field, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.local_url_label = JLabel("Local LLM URL:")
        panel.add(self.local_url_label, gbc)
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.local_url_field = JTextField(config_data.get("local_url", "http://localhost:1234/v1/chat/completions"))
        panel.add(self.local_url_field, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        self.local_api_key_label = JLabel("Local LLM API Key:")
        panel.add(self.local_api_key_label, gbc)
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.local_api_key_field = JPasswordField(30)
        self.local_api_key_field.setText(config_data.get("local_api_key", ""))
        panel.add(self.local_api_key_field, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Model:"), gbc)
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.model_field = JTextField(config_data.get("model", "gpt-3.5-turbo"))
        panel.add(self.model_field, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Timeout (seconds):"), gbc)
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.timeout_field = JTextField(str(config_data.get("timeout", 60)))
        panel.add(self.timeout_field, gbc)
        row += 1
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        button_panel = JPanel()
        save_btn = JButton("Save Settings")
        save_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class SaveAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.save_settings()
        save_btn.addActionListener(SaveAction(self))
        button_panel.add(save_btn)
        test_btn = JButton("Test Connection")
        test_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class TestAction(ActionListener):
            def __init__(self, extension):
                self.extension = extension
            def actionPerformed(self, event):
                self.extension.test_connection()
        test_btn.addActionListener(TestAction(self.extension))
        button_panel.add(test_btn)
        panel.add(button_panel, gbc)
        self.update_backend_fields()
        return panel
    
    def update_backend_fields(self):
        selected = self.backend_combo.getSelectedItem()
        is_openai = selected == "OpenAI"
        is_gemini = selected == "Gemini"
        is_mistral = selected == "Mistral"
        is_groq = selected == "Groq"
        is_local = selected == "Local LLM"
        self.api_key_label.setVisible(is_openai)
        self.api_key_field.setVisible(is_openai)
        self.gemini_api_key_label.setVisible(is_gemini)
        self.gemini_api_key_field.setVisible(is_gemini)
        self.gemini_use_vision_checkbox.setVisible(is_gemini)
        self.mistral_api_key_label.setVisible(is_mistral)
        self.mistral_api_key_field.setVisible(is_mistral)
        self.groq_api_key_label.setVisible(is_groq)
        self.groq_api_key_field.setVisible(is_groq)
        self.local_url_label.setVisible(is_local)
        self.local_url_field.setVisible(is_local)
        self.local_api_key_label.setVisible(is_local)
        self.local_api_key_field.setVisible(is_local)
        config = self.extension.get_config()
        if is_openai:
            self.model_field.setText(config.get("model", "gpt-3.5-turbo"))
        elif is_gemini:
            self.model_field.setText(config.get("gemini_model", "gemini-pro"))
        elif is_mistral:
            self.model_field.setText(config.get("mistral_model", "mistral-small-latest"))
        elif is_groq:
            self.model_field.setText(config.get("groq_model", "mixtral-8x7b-32768"))
        elif is_local:
            self.model_field.setText(config.get("model", "local-model"))
    
    def save_settings(self):
        try:
            backend_map = {"OpenAI": "openai", "Gemini": "gemini", "Mistral": "mistral", "Groq": "groq", "Local LLM": "local"}
            backend = backend_map.get(self.backend_combo.getSelectedItem())
            api_key = "".join(self.api_key_field.getPassword())
            gemini_api_key = "".join(self.gemini_api_key_field.getPassword())
            gemini_use_vision = self.gemini_use_vision_checkbox.isSelected()
            mistral_api_key = "".join(self.mistral_api_key_field.getPassword())
            groq_api_key = "".join(self.groq_api_key_field.getPassword())
            local_url = self.local_url_field.getText().strip()
            local_api_key = "".join(self.local_api_key_field.getPassword())
            model = self.model_field.getText().strip()
            try:
                timeout = int(self.timeout_field.getText().strip())
            except:
                timeout = 60
            settings = {
                "backend": backend,
                "api_key": api_key,
                "gemini_api_key": gemini_api_key,
                "gemini_use_vision": gemini_use_vision,
                "mistral_api_key": mistral_api_key,
                "groq_api_key": groq_api_key,
                "local_url": local_url,
                "local_api_key": local_api_key,
                "model": model,
                "timeout": timeout
            }
            if backend == "gemini":
                settings["gemini_model"] = model
            elif backend == "mistral":
                settings["mistral_model"] = model
            elif backend == "groq":
                settings["groq_model"] = model

            self.extension.save_settings(settings)
        except Exception as e:
            self.append_to_chat("ERROR: Failed to save settings - " + str(e) + "\n")

    def create_chat_panel(self):
        panel = JPanel(BorderLayout())
        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        self.chat_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.chat_area.setLineWrap(True)
        self.chat_area.setWrapStyleWord(True)
        self.chat_area.setText("Chat with Atlas AI for security questions...\n\n")
        chat_scroll = JScrollPane(self.chat_area)
        chat_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self.input_area = JTextArea(4, 50)
        self.input_area.setFont(Font("Monospaced", Font.PLAIN, 14))
        self.input_area.setLineWrap(True)
        self.input_area.setWrapStyleWord(True)
        class ChatKeyListener(KeyAdapter):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def keyPressed(self, event):
                if event.getKeyCode() == KeyEvent.VK_ENTER and not event.isControlDown():
                    self.ui_builder.send_chat_message()
                    event.consume()
        self.input_area.addKeyListener(ChatKeyListener(self))
        input_scroll = JScrollPane(self.input_area)
        input_panel.add(input_scroll, BorderLayout.CENTER)
        button_panel = JPanel()
        send_btn = JButton("Send")
        send_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class SendAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.send_chat_message()
        send_btn.addActionListener(SendAction(self))
        button_panel.add(send_btn)
        clear_btn = JButton("Clear")
        clear_btn.setFont(Font("Arial", Font.PLAIN, 14))
        class ClearAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.chat_area.setText("")
                self.ui_builder.append_to_chat("Chat cleared\n")
        clear_btn.addActionListener(ClearAction(self))
        button_panel.add(clear_btn)
        input_panel.add(button_panel, BorderLayout.EAST)
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, chat_scroll, input_panel)
        split_pane.setDividerLocation(400)
        split_pane.setResizeWeight(0.8)
        panel.add(split_pane, BorderLayout.CENTER)
        return panel

    def create_recon_panel(self):
        panel = JPanel(BorderLayout())
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        target_field = JTextField(30)
        target_field.setToolTipText("Enter a domain or IP address")
        input_panel.add(target_field, BorderLayout.CENTER)
        start_button = JButton("Start Recon")
        input_panel.add(start_button, BorderLayout.EAST)
        panel.add(input_panel, BorderLayout.NORTH)
        self.recon_output_area = JTextArea()
        self.recon_output_area.setEditable(False)
        self.recon_output_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.recon_output_area.setLineWrap(True)
        self.recon_output_area.setWrapStyleWord(True)
        output_scroll = JScrollPane(self.recon_output_area)
        panel.add(output_scroll, BorderLayout.CENTER)
        summarize_button = JButton("Get AI Summary")
        panel.add(summarize_button, BorderLayout.SOUTH)

        class StartReconAction(ActionListener):
            def __init__(self, extension, target_field, output_area):
                self.extension = extension
                self.target_field = target_field
                self.output_area = output_area

            def actionPerformed(self, event):
                target = self.target_field.getText().strip()
                if target:
                    self.output_area.setText("Starting reconnaissance on: " + target + "\n\n")
                    self.extension.start_reconnaissance(target)

        start_button.addActionListener(StartReconAction(self.extension, target_field, self.recon_output_area))
        
        class SummarizeReconAction(ActionListener):
            def __init__(self, extension, output_area):
                self.extension = extension
                self.output_area = output_area

            def actionPerformed(self, event):
                recon_results = self.output_area.getText()
                if recon_results:
                    self.extension.summarize_recon_results(recon_results)

        summarize_button.addActionListener(SummarizeReconAction(self.extension, self.recon_output_area))

        return panel

    def append_to_chat(self, text):
        if self.chat_area:
            def append_task():
                self.chat_area.append(text)
                self.chat_area.setCaretPosition(self.chat_area.getDocument().getLength())
            SwingUtilities.invokeLater(append_task)

    def show_in_analysis_panel(self, text):
        if self.analysis_area:
            self.analysis_area.setText(text)
            self.analysis_area.setCaretPosition(0)

    def show_actionable_command(self, command):
        if self.actionable_command_panel:
            self.command_field.setText(command)
            self.actionable_command_panel.setVisible(True)

    def hide_actionable_command(self):
        if self.actionable_command_panel:
            self.actionable_command_panel.setVisible(False)

    def send_chat_message(self):
        message = self.input_area.getText().strip()
        if not message:
            return
        self.input_area.setText("")
        self.extension.send_chat_message(message)

    def create_config_panel(self):
        panel = JPanel(BorderLayout())
        config_tabs = JTabbedPane()
        settings_panel = self.create_settings_panel()
        config_tabs.addTab("Settings", settings_panel)
        chat_panel = self.create_chat_panel()
        config_tabs.addTab("Chat", chat_panel)
        panel.add(config_tabs, BorderLayout.CENTER)
        return panel

    def create_enhanced_analysis_panel(self):
        panel = JPanel(BorderLayout())
        title_panel = JPanel()
        title = JLabel("Security Analysis Results")
        title.setFont(Font("Arial", Font.BOLD, 16))
        title_panel.add(title)
        panel.add(title_panel, BorderLayout.NORTH)
        self.analysis_tabbed_pane = JTabbedPane()
        general_panel = JPanel(BorderLayout())
        self.analysis_area = JTextArea()
        self.analysis_area.setEditable(False)
        self.analysis_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.analysis_area.setLineWrap(True)
        self.analysis_area.setWrapStyleWord(True)
        self.analysis_area.setText("Analysis results will appear here...\n\nUse the context menu in Burp to analyze requests, responses, or scanner findings.")
        analysis_scroll = JScrollPane(self.analysis_area)
        general_panel.add(analysis_scroll, BorderLayout.CENTER)

        self.actionable_command_panel = JPanel(BorderLayout())
        self.actionable_command_panel.setBorder(BorderFactory.createTitledBorder("Actionable Command"))
        self.command_field = JTextField()
        self.command_field.setEditable(False)
        self.actionable_command_panel.add(self.command_field, BorderLayout.CENTER)
        buttons = JPanel()
        copy_button = JButton("Copy")
        run_button = JButton("Run")
        buttons.add(copy_button)
        buttons.add(run_button)
        self.actionable_command_panel.add(buttons, BorderLayout.EAST)
        general_panel.add(self.actionable_command_panel, BorderLayout.SOUTH)
        self.hide_actionable_command()

        class CopyCommandAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                toolkit = Toolkit.getDefaultToolkit()
                clipboard = toolkit.getSystemClipboard()
                clipboard.setContents(StringSelection(self.ui_builder.command_field.getText()), None)
        copy_button.addActionListener(CopyCommandAction(self))

        class RunCommandAction(ActionListener):
            def __init__(self, extension, ui_builder):
                self.extension = extension
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                command = self.ui_builder.command_field.getText()
                self.extension.run_terminal_command(command)
        run_button.addActionListener(RunCommandAction(self.extension, self))

        self.analysis_tabbed_pane.addTab("General Analysis", general_panel)
        scanner_panel = JPanel(BorderLayout())
        self.scanner_analysis_area = JTextArea()
        self.scanner_analysis_area.setEditable(False)
        self.scanner_analysis_area.setFont(Font("Monospiced", Font.BOLD, 17))
        self.scanner_analysis_area.setLineWrap(True)
        self.scanner_analysis_area.setWrapStyleWord(True)
        self.scanner_analysis_area.setText("Scanner finding analyses will appear here...\n\nRight-click on scanner issues and select 'Atlas AI: Analyze & Explain Finding' or 'Atlas AI: Suggest Exploitation'.")
        scanner_scroll = JScrollPane(self.scanner_analysis_area)
        scanner_panel.add(scanner_scroll, BorderLayout.CENTER)
        self.analysis_tabbed_pane.addTab("Scanner Findings", scanner_panel)
        panel.add(self.analysis_tabbed_pane, BorderLayout.CENTER)
        return panel
