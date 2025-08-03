from javax.swing import (
    JPanel, JLabel, JCheckBox, JTextField, JButton, JTextArea,
    JScrollPane, JTable, JSplitPane, BoxLayout, Box, JTabbedPane
)
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel
from java.awt import BorderLayout, Dimension, FlowLayout, Color
from java.awt.event import MouseAdapter

# Render colors for authentication/authorization columns
class AuthCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        if value == "Yes":
            component.setBackground(Color(144, 238, 144))  # Green
        elif value == "No":
            component.setBackground(Color(255, 182, 193))  # Red
        else:
            component.setBackground(Color.white)
        return component

# Disable editing of the table
class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

# Mouse listener to handle clicks on the table
class TableClickListener(MouseAdapter):
    def __init__(self, panel):
        self.panel = panel

    def mouseClicked(self, event):
        view_row = self.panel.table.getSelectedRow()
        if view_row >= 0:
            model_row = self.panel.table.convertRowIndexToModel(view_row)
            if model_row < len(self.panel._row_data):
                rr_map = self.panel._row_data[model_row]
                self.panel.show_request_response_variants(rr_map)
                self.panel.tabbed_panel.setSelectedIndex(1)

class ConfigPanel:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._row_data = []

        self._build_ui()

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())

        ## LEFT TABBED PANEL
        self.tabbed_panel = JTabbedPane()

        # ----- Tab 1: Configuration -----
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

        self.crawl_checkbox = JCheckBox("Enable Crawling", True)
        self.proxy_checkbox = JCheckBox("Enable Proxy History Analysis", True)

        option_panel = JPanel()
        option_panel.setLayout(BoxLayout(option_panel, BoxLayout.Y_AXIS))
        option_panel.add(self.crawl_checkbox)
        option_panel.add(self.proxy_checkbox)

        self.auth_header_field = JTextArea(3, 20)
        self.high_cred_field = JTextArea(3, 20)
        self.low_cred_field = JTextArea(3, 20)

        self.auth_header_scroll = JScrollPane(self.auth_header_field)
        self.high_cred_scroll = JScrollPane(self.high_cred_field)
        self.low_cred_scroll = JScrollPane(self.low_cred_field)

        self.api_keyword_field = JTextField("/", 20)

        self.start_button = JButton("Start API Discovery")
        self.save_button = JButton("Save Results to CSV")
        self.clear_button = JButton("Clear Results")
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        button_panel.add(self.start_button)
        button_panel.add(self.save_button)
        button_panel.add(self.clear_button)

        self.log_area = JTextArea(8, 36)
        self.log_area.setEditable(False)
        self.log_scroll = JScrollPane(self.log_area)

        self.control_panel.add(option_panel)
        self.control_panel.add(Box.createRigidArea(Dimension(0, 10)))
        self.control_panel.add(labeled_row("Auth Header:", self.auth_header_scroll, 60))
        self.control_panel.add(labeled_row("High-Priv Cred:", self.high_cred_scroll, 60))
        self.control_panel.add(labeled_row("Low-Priv Cred:", self.low_cred_scroll, 60))
        self.control_panel.add(labeled_row("API Keyword:", self.api_keyword_field, 24))
        self.control_panel.add(button_panel)
        self.control_panel.add(self.log_scroll)

        self.tabbed_panel.addTab("Configuration", self.control_panel)

        # ----- Tab 2: Request/Response Variants -----
        self.variants_panel = JPanel()
        self.variants_panel.setLayout(BoxLayout(self.variants_panel, BoxLayout.Y_AXIS))

        def create_editor_tab(title):
            req_editor = self.callbacks.createMessageEditor(None, False)
            res_editor = self.callbacks.createMessageEditor(None, False)
            tabbed = JTabbedPane()
            tabbed.addTab("{} Request".format(title), req_editor.getComponent())
            tabbed.addTab("{} Response".format(title), res_editor.getComponent())
            return tabbed, req_editor, res_editor

        self.unauth_tab, self.unauth_req_editor, self.unauth_res_editor = create_editor_tab("Unauthenticated")
        self.low_tab, self.low_req_editor, self.low_res_editor = create_editor_tab("Low-Priv")
        self.high_tab, self.high_req_editor, self.high_res_editor = create_editor_tab("High-Priv")

        self.variants_panel.add(self.unauth_tab)
        self.variants_panel.add(self.low_tab)
        self.variants_panel.add(self.high_tab)

        self.tabbed_panel.addTab("Request Variants", self.variants_panel)

        # Table (Right side)
        self.table_columns = [
            "Endpoint", "HTTP Method", "Parameters",
            "Authentication Required", "Authorization Enforced"
        ]
        self.table_model = NonEditableTableModel(self.table_columns, 0)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.getColumnModel().getColumn(3).setCellRenderer(AuthCellRenderer())
        self.table.getColumnModel().getColumn(4).setCellRenderer(AuthCellRenderer())
        self.table_scroll = JScrollPane(self.table)

        self.table.addMouseListener(TableClickListener(self))

        self.split_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.split_panel.setLeftComponent(self.tabbed_panel)
        self.split_panel.setRightComponent(self.table_scroll)
        self.split_panel.setDividerLocation(470)

        self.main_panel.add(self.split_panel, BorderLayout.CENTER)

    def show_request_response_variants(self, rr_map):
        for label, req_editor, res_editor in [
            ("Unauthenticated", self.unauth_req_editor, self.unauth_res_editor),
            ("Low-Priv", self.low_req_editor, self.low_res_editor),
            ("High-Priv", self.high_req_editor, self.high_res_editor),
        ]:
            rr = rr_map.get(label)
            if rr:
                req_editor.setMessage(rr.getRequest(), True)
                res_editor.setMessage(rr.getResponse(), False)
            else:
                req_editor.setMessage(None, True)
                res_editor.setMessage(None, False)

    def get_main_panel(self): return self.main_panel
    def is_crawling_enabled(self): return self.crawl_checkbox.isSelected()
    def is_proxy_history_enabled(self): return self.proxy_checkbox.isSelected()
    def get_auth_header_name(self): return self.auth_header_field.getText().strip()
    def get_high_cred(self): return self.high_cred_field.getText().strip()
    def get_low_cred(self): return self.low_cred_field.getText().strip()
    def get_api_keyword(self): return self.api_keyword_field.getText().strip().lower()
    def add_log(self, msg): self.log_area.append(msg + "\n")

    def add_endpoint_result(self, endpoint, method, params, auth_required, authz_enforced, rr_map):
        row = [endpoint, method, params, auth_required, authz_enforced]
        self.table_model.addRow(row)
        self._row_data.append(rr_map)

    def clear_table(self):
        self.table_model.setRowCount(0)
        self._row_data = []

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
