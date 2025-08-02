from javax.swing import (
    JPanel, JLabel, JCheckBox, JTextField, JButton, JTextArea,
    JScrollPane, JTable, JSplitPane, BoxLayout, Box
)
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel
from java.awt import BorderLayout, Dimension, FlowLayout, Color


class AuthCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        if value == "Yes":
            component.setBackground(Color(144, 238, 144))  # Light green
        elif value == "No":
            component.setBackground(Color(255, 182, 193))  # Light red
        else:
            component.setBackground(Color.white)
        return component


class ConfigPanel:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._build_ui()

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())

        # LEFT: Controls
        self.control_panel = JPanel()
        self.control_panel.setLayout(BoxLayout(self.control_panel, BoxLayout.Y_AXIS))

        def labeled_row(label_text, field, height=24):
            panel = JPanel(FlowLayout(FlowLayout.LEFT))
            label = JLabel(label_text)
            label.setPreferredSize(Dimension(140, height))
            field.setPreferredSize(Dimension(220, height))
            panel.add(label)
            panel.add(field)
            return panel

        # Checkboxes
        self.crawl_checkbox = JCheckBox("Enable Crawling", True)
        self.proxy_checkbox = JCheckBox("Enable Proxy History Analysis", True)
        option_panel = JPanel()
        option_panel.setLayout(BoxLayout(option_panel, BoxLayout.Y_AXIS))
        option_panel.add(self.crawl_checkbox)
        option_panel.add(self.proxy_checkbox)

        # Auth fields
        self.auth_header_field = JTextArea(3, 20)
        self.high_cred_field = JTextArea(3, 20)
        self.low_cred_field = JTextArea(3, 20)
        self.auth_header_scroll = JScrollPane(self.auth_header_field)
        self.high_cred_scroll = JScrollPane(self.high_cred_field)
        self.low_cred_scroll = JScrollPane(self.low_cred_field)

        # API keyword
        self.api_keyword_field = JTextField("/", 20)

        # Buttons
        self.start_button = JButton("Start API Discovery")
        self.save_button = JButton("Save Results to CSV")
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        button_panel.add(self.start_button)
        button_panel.add(self.save_button)

        # Log output
        self.log_area = JTextArea(8, 36)
        self.log_area.setEditable(False)
        self.log_scroll = JScrollPane(self.log_area)

        # Assemble control panel
        self.control_panel.add(option_panel)
        self.control_panel.add(Box.createRigidArea(Dimension(0, 10)))
        self.control_panel.add(labeled_row("Auth Header:", self.auth_header_scroll, 60))
        self.control_panel.add(labeled_row("High-Priv Cred:", self.high_cred_scroll, 60))
        self.control_panel.add(labeled_row("Low-Priv Cred:", self.low_cred_scroll, 60))
        self.control_panel.add(labeled_row("API Keyword:", self.api_keyword_field, 24))
        self.control_panel.add(button_panel)
        self.control_panel.add(self.log_scroll)

        # RIGHT: Table
        self.table_columns = [
            "Endpoint",
            "HTTP Method",
            "Parameters",
            "Authentication Required",
            "Authorization Enforced"
        ]
        self.table_model = DefaultTableModel(self.table_columns, 0)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)

        # Set custom cell renderer
        self.table.getColumnModel().getColumn(3).setCellRenderer(AuthCellRenderer())
        self.table.getColumnModel().getColumn(4).setCellRenderer(AuthCellRenderer())

        self.table_scroll = JScrollPane(self.table)

        # Split layout
        self.split_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.split_panel.setLeftComponent(self.control_panel)
        self.split_panel.setRightComponent(self.table_scroll)
        self.split_panel.setDividerLocation(430)

        self.main_panel.add(self.split_panel, BorderLayout.CENTER)

    def get_main_panel(self):
        return self.main_panel

    # Getters
    def is_crawling_enabled(self):
        return self.crawl_checkbox.isSelected()

    def is_proxy_history_enabled(self):
        return self.proxy_checkbox.isSelected()

    def get_auth_header_name(self):
        return self.auth_header_field.getText().strip()

    def get_high_cred(self):
        return self.high_cred_field.getText().strip()

    def get_low_cred(self):
        return self.low_cred_field.getText().strip()

    def get_api_keyword(self):
        return self.api_keyword_field.getText().strip().lower()

    def add_log(self, msg):
        self.log_area.append(msg + "\n")

    def add_endpoint_result(self, endpoint, method, params, auth_required, authz_enforced):
        row = [endpoint, method, params, auth_required, authz_enforced]
        self.table_model.addRow(row)

    def clear_table(self):
        self.table_model.setRowCount(0)

    def clear_log(self):
        self.log_area.setText("")

    def get_all_table_rows(self):
        rows = []
        for i in range(self.table_model.getRowCount()):
            row = []
            for j in range(self.table_model.getColumnCount()):
                row.append(str(self.table_model.getValueAt(i, j)))
            rows.append(tuple(row))
        return rows
