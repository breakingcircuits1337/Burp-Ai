# -*- coding: utf-8 -*-
# Atlas AI UI Builder

from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color
from java.awt.event import ActionListener, KeyAdapter, KeyEvent
from javax.swing import (
    JPanel, JLabel, JButton, JTextArea, JScrollPane,
    JTextField, JPasswordField, BorderFactory, JComboBox,
    JSplitPane, Box, BoxLayout, SwingUtilities, JTabbedPane
)
import threading

class AtlasUIBuilder:
    """Handles UI creation for Atlas AI extension."""
    
    def __init__(self, extension):
        self.extension = extension
        self.chat_area = None
        self.analysis_area = None
        self.input_area = None
        
        # UI components that need to be accessible
        self.backend_combo = None
        self.api_key_field = None
        self.gemini_api_key_field = None
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
    
    def create_settings_panel(self):
        """Create settings panel."""
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        
        row = 0
        
        # Title
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.anchor = GridBagConstraints.CENTER
        title = JLabel("AI Backend Configuration")
        title.setFont(Font("Arial", Font.BOLD, 18))
        panel.add(title, gbc)
        
        row += 1
        
        # Backend selection
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 1
        gbc.anchor = GridBagConstraints.WEST
        panel.add(JLabel("Backend:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.backend_combo = JComboBox(["OpenAI", "Gemini", "Mistral", "Groq", "Local LLM"])
        config_data = self.extension.get_config().get_all()
        backend_map = {
            "openai": "OpenAI",
            "gemini": "Gemini",
            "mistral": "Mistral",
            "groq": "Groq",
            "local": "Local LLM"
        }
        self.backend_combo.setSelectedItem(backend_map.get(config_data.get("backend"), "OpenAI"))
        
        class BackendAction(ActionListener):
            def __init__(self, ui_builder):
                self.ui_builder = ui_builder
            def actionPerformed(self, event):
                self.ui_builder.update_backend_fields()
        
        self.backend_combo.addActionListener(BackendAction(self))
        panel.add(self.backend_combo, gbc)
        
        row += 1
        
        # API Key (OpenAI)
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
        
        # API Key (Gemini)
        self.gemini_api_key_label = JLabel("Gemini API Key:")
        panel.add(self.gemini_api_key_label, gbc)
        
        self.gemini_api_key_field = JPasswordField(30)
        self.gemini_api_key_field.setText(config_data.get("gemini_api_key", ""))
        panel.add(self.gemini_api_key_field, gbc)
        
        # API Key (Mistral)
        self.mistral_api_key_label = JLabel("Mistral API Key:")
        panel.add(self.mistral_api_key_label, gbc)
        
        self.mistral_api_key_field = JPasswordField(30)
        self.mistral_api_key_field.setText(config_data.get("mistral_api_key", ""))
        panel.add(self.mistral_api_key_field, gbc)

        # API Key (Groq)
        self.groq_api_key_label = JLabel("Groq API Key:")
        panel.add(self.groq_api_key_label, gbc)

        self.groq_api_key_field = JPasswordField(30)
        self.groq_api_key_field.setText(config_data.get("groq_api_key", ""))
        panel.add(self.groq_api_key_field, gbc)
        
        row += 1
        
        # Local LLM URL
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
        
        # Local LLM API Key
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
        
        # Model
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Model:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.model_field = JTextField(config_data.get("model", "gpt-3.5-turbo"))
        panel.add(self.model_field, gbc)
        
        row += 1
        
        # Timeout
        gbc.gridx = 0
        gbc.gridy = row
        gbc.fill = GridBagConstraints.NONE
        panel.add(JLabel("Timeout (seconds):"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self.timeout_field = JTextField(str(config_data.get("timeout", 60)))
        panel.add(self.timeout_field, gbc)
        
        row += 1
        
        # Buttons
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
        
        # Update field visibility
        self.update_backend_fields()
        
        return panel
    
    def update_backend_fields(self):
        """Update field visibility based on backend selection."""
        selected = self.backend_combo.getSelectedItem()
        
        is_openai = selected == "OpenAI"
        is_gemini = selected == "Gemini"
        is_mistral = selected == "Mistral"
        is_groq = selected == "Groq"
        is_local = selected == "Local LLM"
        
        # API Key fields
        self.api_key_label.setVisible(is_openai)
        self.api_key_field.setVisible(is_openai)
        self.gemini_api_key_label.setVisible(is_gemini)
        self.gemini_api_key_field.setVisible(is_gemini)
        self.mistral_api_key_label.setVisible(is_mistral)
        self.mistral_api_key_field.setVisible(is_mistral)
        self.groq_api_key_label.setVisible(is_groq)
        self.groq_api_key_field.setVisible(is_groq)
        
        # Local LLM fields
        self.local_url_label.setVisible(is_local)
        self.local_url_field.setVisible(is_local)
        self.local_api_key_label.setVisible(is_local)
        self.local_api_key_field.setVisible(is_local)
        
        # Update model field based on backend
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
        """Save settings from UI."""
        try:
            backend_map = {
                "OpenAI": "openai",
                "Gemini": "gemini",
                "Mistral": "mistral",
                "Groq": "groq",
                "Local LLM": "local"
            }
            backend = backend_map.get(self.backend_combo.getSelectedItem())
            
            api_key = "".join(self.api_key_field.getPassword())
            gemini_api_key = "".join(self.gemini_api_key_field.getPassword())
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
                "mistral_api_key": mistral_api_key,
                "groq_api_key": groq_api_key,
                "local_url": local_url,
                "local_api_key": local_api_key,
                "model": model,
                "timeout": timeout
            }
            
            # Save the correct model based on backend
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
        """Create chat interface."""
        panel = JPanel(BorderLayout())
        
        # Chat area
        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        self.chat_area.setFont(Font("Monospaced", Font.BOLD, 17))  # Bold 17pt font for AI responses
        self.chat_area.setLineWrap(True)
        self.chat_area.setWrapStyleWord(True)
        self.chat_area.setText("Chat with Atlas AI for security questions...\n\n")
        
        chat_scroll = JScrollPane(self.chat_area)
        chat_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        
        # Input area
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        self.input_area = JTextArea(4, 50)
        self.input_area.setFont(Font("Monospaced", Font.PLAIN, 14))  # Bigger font
        self.input_area.setLineWrap(True)
        self.input_area.setWrapStyleWord(True)
        
        # Enter key handler
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
        
        # Buttons
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
        
        # Split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, chat_scroll, input_panel)
        split_pane.setDividerLocation(400)
        split_pane.setResizeWeight(0.8)
        
        panel.add(split_pane, BorderLayout.CENTER)
        
        return panel

    def append_to_chat(self, text):
        """Append text to chat area."""
        if self.chat_area:
            self.chat_area.append(text)
            self.chat_area.setCaretPosition(self.chat_area.getDocument().getLength())

    def show_in_analysis_panel(self, text):
        """Show text in analysis panel."""
        if self.analysis_area:
            self.analysis_area.setText(text)
            self.analysis_area.setCaretPosition(0)

    def send_chat_message(self):
        """Send chat message."""
        message = self.input_area.getText().strip()
        if not message:
            return
        
        self.input_area.setText("")
        self.extension.send_chat_message(message)

    def create_config_panel(self):
        """Create combined config panel with settings and help."""
        panel = JPanel(BorderLayout())
        
        # Create tabbed pane for config
        config_tabs = JTabbedPane()
        
        # Settings tab
        settings_panel = self.create_settings_panel()
        config_tabs.addTab("Settings", settings_panel)
        
        # Chat tab
        chat_panel = self.create_chat_panel()
        config_tabs.addTab("Chat", chat_panel)

        panel.add(config_tabs, BorderLayout.CENTER)
        return panel

    def create_enhanced_analysis_panel(self):
        """Create enhanced analysis panel with tabs for different analysis types."""
        panel = JPanel(BorderLayout())
        
        # Title
        title_panel = JPanel()
        title = JLabel("Security Analysis Results")
        title.setFont(Font("Arial", Font.BOLD, 16))
        title_panel.add(title)
        panel.add(title_panel, BorderLayout.NORTH)
        
        # Tabbed pane for different analysis types
        self.analysis_tabbed_pane = JTabbedPane()
        
        # General Analysis tab (for context menu analyses)
        general_panel = JPanel(BorderLayout())
        self.analysis_area = JTextArea()
        self.analysis_area.setEditable(False)
        self.analysis_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.analysis_area.setLineWrap(True)
        self.analysis_area.setWrapStyleWord(True)
        self.analysis_area.setText("Analysis results will appear here...\n\nUse the context menu in Burp to analyze requests, responses, or scanner findings.")
        
        analysis_scroll = JScrollPane(self.analysis_area)
        general_panel.add(analysis_scroll, BorderLayout.CENTER)
        
        self.analysis_tabbed_pane.addTab("General Analysis", general_panel)
        
        # Scanner Findings tab
        scanner_panel = JPanel(BorderLayout())
        self.scanner_analysis_area = JTextArea()
        self.scanner_analysis_area.setEditable(False)
        self.scanner_analysis_area.setFont(Font("Monospaced", Font.BOLD, 17))
        self.scanner_analysis_area.setLineWrap(True)
        self.scanner_analysis_area.setWrapStyleWord(True)
        self.scanner_analysis_area.setText("Scanner finding analyses will appear here...\n\nRight-click on scanner issues and select 'Atlas AI: Analyze & Explain Finding' or 'Atlas AI: Suggest Exploitation'.")
        
        scanner_scroll = JScrollPane(self.scanner_analysis_area)
        scanner_panel.add(scanner_scroll, BorderLayout.CENTER)
        
        self.analysis_tabbed_pane.addTab("Scanner Findings", scanner_panel)
        
        panel.add(self.analysis_tabbed_pane, BorderLayout.CENTER)
        return panel
