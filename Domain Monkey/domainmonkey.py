import re
import whois
import sys
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QTextBrowser, 
                             QFileDialog, QLabel, QMessageBox, QProgressBar, QFrame, QTabWidget, QDialog, QCheckBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QIcon
import datetime
import logging
import pprint

# Set up logging to console
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

domains = []
results = []
rate_limit_reached = False
checked_domains = set()
remember_choice = None
stop_checking = False

class Worker(QThread):
    update_progress = pyqtSignal(int)
    update_result = pyqtSignal(str, str)
    finished = pyqtSignal()
    rate_limit_reached_signal = pyqtSignal()

    def __init__(self, domains):
        super().__init__()
        self.domains = domains
        logger.debug("Worker thread initialized with domains: {}".format(domains))

    def run(self):
        global results, rate_limit_reached, checked_domains, stop_checking
        total_domains = len(self.domains)
        logger.debug("Starting domain check for {} domains".format(total_domains))
        for i, dom in enumerate(self.domains):
            if stop_checking:
                logger.debug("Stopping check as stop_checking is True")
                return
            dom = self.sanitize_domain(dom)
            if dom and dom not in checked_domains:
                logger.debug("Checking domain: {}".format(dom))
                result = self.check_domain(dom)
                if result == "RATE_LIMIT":
                    logger.warning("Rate limit reached while checking domain: {}".format(dom))
                    rate_limit_reached = True
                    self.rate_limit_reached_signal.emit()
                    return
                results.append((dom, result))
                checked_domains.add(dom)
                self.update_result.emit(dom, result)
            self.update_progress.emit(int((i + 1) / total_domains * 100))
        self.finished.emit()
        logger.debug("Domain check finished for all domains")

    def sanitize_domain(self, domain):
        # Remove protocols (http, https) and www prefixes
        domain = re.sub(r'^https?://(www\.)?', '', domain)
        # Validate the domain using a regex pattern
        if re.match(r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$', domain):
            return domain
        return None

    def check_domain(self, domain):
        try:
            logger.debug("Checking domain: {}".format(domain))
            details = whois.whois(domain)
            details_formatted = pprint.pformat(details)
            logger.debug("Raw WHOIS details for {}: \n{}".format(domain, details_formatted))
            
            # Determine if the domain is unavailable based on multiple factors
            if details.domain_name:
                if details.status:
                    logger.debug("Domain {} is UNAVAILABLE, details: \n{}".format(domain, details_formatted))
                    return "UNAVAILABLE"
                elif details.creation_date:
                    logger.debug("Domain {} is UNAVAILABLE, details: \n{}".format(domain, details_formatted))
                    return "UNAVAILABLE"
                elif details.name_servers and len(details.name_servers) > 0:
                    logger.debug("Domain {} is UNAVAILABLE, details: \n{}".format(domain, details_formatted))
                    return "UNAVAILABLE"
                else:
                    logger.debug("Domain {} might still be AVAILABLE, details: \n{}".format(domain, details_formatted))
                    return "AVAILABLE"
            else:
                logger.debug("Domain {} is AVAILABLE, details: \n{}".format(domain, details_formatted))
                return "AVAILABLE"
        except Exception as e:
            logger.error("Error checking domain {}: {}".format(domain, e))
            if "rate limit" in str(e).lower():
                return "RATE_LIMIT"
            return "AVAILABLE"

class LoadOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Load new domain list")
        self.setGeometry(300, 300, 400, 200)
        layout = QVBoxLayout()

        self.export_btn = QPushButton("Export current results and load new list", self)
        self.export_btn.clicked.connect(self.export_and_load)
        self.export_btn.setStyleSheet("background-color: #0078d7; color: white;")
        layout.addWidget(self.export_btn)

        self.add_btn = QPushButton("Load new list and add to current list", self)
        self.add_btn.clicked.connect(self.add_to_current)
        self.add_btn.setStyleSheet("background-color: #005fa1; color: white;")
        layout.addWidget(self.add_btn)

        self.discard_btn = QPushButton("Load new list and discard current results", self)
        self.discard_btn.clicked.connect(self.discard_and_load)
        self.discard_btn.setStyleSheet("background-color: #800080; color: white;")
        layout.addWidget(self.discard_btn)

        self.remember_choice_checkbox = QCheckBox("Remember choice for this session", self)
        layout.addWidget(self.remember_choice_checkbox)

        self.setLayout(layout)
        self.choice = None

    def export_and_load(self):
        self.choice = "export"
        self.accept()

    def add_to_current(self):
        self.choice = "add"
        self.accept()

    def discard_and_load(self):
        self.choice = "discard"
        self.accept()

    def get_choice(self):
        return self.choice, self.remember_choice_checkbox.isChecked()

class DomainMonkey(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Domain Monkey')
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon('Icon.ico'))

        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            QLabel {
                font-size: 16px;
                color: #333;
            }
            QLineEdit {
                padding: 8px;
                font-size: 16px;
                border: 1px solid #ccc;
                border-radius: 4px;
                margin: 5px 0;
            }
            QTextBrowser {
                background-color: #fff;
                border: 1px solid #ccc;
                padding: 10px;
                font-size: 16px;
                border-radius: 4px;
                margin: 0px;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                padding: 10px;
                font-size: 16px;
                border: none;
                border-radius: 4px;
                margin: 5px 0;
            }
            QPushButton:hover {
                background-color: #005fa1;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 4px;
                text-align: center;
                font-size: 16px;
                color: black;
                margin: 10px 0;
            }
            QProgressBar::chunk {
                background-color: #28a745;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QTabBar::tab {
                background: #0078d7;
                color: white;
                padding: 10px;
                border-radius: 4px;
                margin: 1px;
            }
            QTabBar::tab:selected, QTabBar::tab:hover {
                background: #005fa1;
            }
            QDialog {
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 10px;
            }
            a {
                color: #0078d7;
                text-decoration: none;
            }
            a:hover {
                color: #005fa1;
            }
        """)

        main_layout = QVBoxLayout()

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_checker_tab(), "Domain Checker")
        self.tabs.addTab(self.create_info_tab(), "Info")

        main_layout.addWidget(self.tabs)

        self.setLayout(main_layout)

    def create_checker_tab(self):
        checker_tab = QWidget()
        layout = QVBoxLayout()

        header_layout = QHBoxLayout()

        self.domain_label = QLabel('Enter Domain:')
        header_layout.addWidget(self.domain_label)

        self.domain_entry = QLineEdit(self)
        header_layout.addWidget(self.domain_entry)

        self.check_button = QPushButton('Check Domain', self)
        self.check_button.clicked.connect(self.check_single_domain)
        header_layout.addWidget(self.check_button)

        layout.addLayout(header_layout)

        self.upload_button = QPushButton('Upload Domain List (.txt)', self)
        self.upload_button.clicked.connect(self.load_domains)
        layout.addWidget(self.upload_button)

        self.run_button = QPushButton('Check Domains from List', self)
        self.run_button.clicked.connect(self.toggle_check)
        self.run_button.setEnabled(False)
        layout.addWidget(self.run_button)

        self.export_button = QPushButton('Export Results', self)
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        layout.addWidget(self.export_button)

        self.load_status = QLabel('No domains loaded')
        layout.addWidget(self.load_status)

        self.progress = QProgressBar(self)
        layout.addWidget(self.progress)

        result_layout = QHBoxLayout()

        unavailable_frame = QFrame(self)
        unavailable_frame.setFrameShape(QFrame.StyledPanel)
        unavailable_layout = QVBoxLayout()
        unavailable_label = QLabel('Unavailable Domains:')
        unavailable_layout.addWidget(unavailable_label)
        self.unavailable_text = QTextBrowser(self)
        self.unavailable_text.setReadOnly(True)
        self.unavailable_text.setOpenExternalLinks(True)
        self.unavailable_text.setStyleSheet("margin: 0px; padding: 0px;")
        self.unavailable_text.setMinimumHeight(200)
        unavailable_layout.addWidget(self.unavailable_text)
        unavailable_frame.setLayout(unavailable_layout)

        available_frame = QFrame(self)
        available_frame.setFrameShape(QFrame.StyledPanel)
        available_layout = QVBoxLayout()
        available_label = QLabel('Available Domains:')
        available_layout.addWidget(available_label)
        self.available_text = QTextBrowser(self)
        self.available_text.setReadOnly(True)
        self.available_text.setOpenExternalLinks(True)
        self.available_text.setStyleSheet("margin: 0px; padding: 0px;")
        self.available_text.setMinimumHeight(200)
        available_layout.addWidget(self.available_text)
        available_frame.setLayout(available_layout)

        result_layout.addWidget(unavailable_frame)
        result_layout.addWidget(available_frame)

        layout.addLayout(result_layout)

        checker_tab.setLayout(layout)

        return checker_tab

    def create_info_tab(self):
        info_tab = QWidget()
        layout = QVBoxLayout()

        info_text = QLabel("""
            <h1>Welcome to Domain Monkey</h1>
            <p>Domain Monkey helps you quickly check the availability of domain names.</p>
            <p>Upload a list of domains or enter a single domain to check its availability.</p>
            <p>Export the results in various formats for your convenience.</p>
            <p>For more information, visit <a href='http://www.ExtensionMonkey.de'>ExtensionMonkey.de</a></p>
        """)
        info_text.setOpenExternalLinks(True)

        layout.addWidget(info_text)

        info_tab.setLayout(layout)

        return info_tab

    def load_domains(self):
        global domains, results, checked_domains, remember_choice, stop_checking
        stop_checking = True
        logger.debug("Loading new domain list")

        if results and remember_choice is None:
            dialog = LoadOptionsDialog(self)
            if dialog.exec_():
                choice, remember = dialog.get_choice()
                logger.debug("User choice: {}, Remember: {}".format(choice, remember))
                if remember:
                    remember_choice = choice

                if choice == "export":
                    self.export_results()
                    domains = []
                    results = []
                    checked_domains.clear()
                    self.unavailable_text.clear()
                    self.available_text.clear()
                elif choice == "discard":
                    domains = []
                    results = []
                    checked_domains.clear()
                    self.unavailable_text.clear()
                    self.available_text.clear()

        if remember_choice == "export":
            self.export_results()
            domains = []
            results = []
            checked_domains.clear()
            self.unavailable_text.clear()
            self.available_text.clear()
        elif remember_choice == "discard":
            domains = []
            results = []
            checked_domains.clear()
            self.unavailable_text.clear()
            self.available_text.clear()

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Text File", "", "Text Files (*.txt)", options=options)
        if file_path:
            with open(file_path, 'r') as f:
                new_domains = f.read().splitlines()
            if new_domains:  # Check if the list is not empty
                logger.debug("Loaded {} new domains from file".format(len(new_domains)))
                # Sanitize and validate domains
                valid_domains = [self.sanitize_domain(domain) for domain in new_domains if self.sanitize_domain(domain)]
                if valid_domains:
                    domains.extend(valid_domains)
                    self.load_status.setText(f"{len(domains)} domains loaded")
                    self.run_button.setEnabled(True)
                    self.run_button.setStyleSheet("background-color: #28a745; color: white;")
                else:
                    logger.warning("No valid domains found in the loaded file")
                    QMessageBox.warning(self, "Error", "The loaded file contains no valid domains. Please select a valid file.")
            else:
                logger.warning("The loaded file is empty")
                QMessageBox.warning(self, "Error", "The loaded file is empty. Please select a valid file.")

    def toggle_check(self):
        global stop_checking
        if self.run_button.text() in ['Check Domains from List', 'Continue Checking']:
            stop_checking = False
            self.run_button.setText('Stop Checking')
            self.run_button.setStyleSheet("background-color: #ff4c4c; color: white;")
            self.start_check()
        else:
            stop_checking = True
            self.run_button.setText('Continue Checking')
            self.run_button.setStyleSheet("background-color: #28a745; color: white;")

    def start_check(self):
        global stop_checking
        stop_checking = False
        self.worker = Worker(domains)
        self.worker.update_progress.connect(self.update_progress)
        self.worker.update_result.connect(self.update_result)
        self.worker.finished.connect(self.check_finished)
        self.worker.rate_limit_reached_signal.connect(self.show_rate_limit_message)
        self.worker.start()

    def update_progress(self, value):
        self.progress.setValue(value)

    def update_result(self, domain, result):
        domain_link = f"<a href='http://{domain}' style='color: #0078d7; text-decoration: none;'>{domain}</a>"
        if result == "UNAVAILABLE":
            current_text = self.unavailable_text.toHtml().strip()
            new_text = current_text + f"<div style='margin-bottom: 2px; margin-top: 0px;'>{domain_link}</div>"
            self.unavailable_text.setHtml(new_text)
        elif result == "AVAILABLE":
            current_text = self.available_text.toHtml().strip()
            new_text = current_text + f"<div style='margin-bottom: 2px; margin-top: 0px;'>{domain_link}</div>"
            self.available_text.setHtml(new_text)
        results.append((domain, result))

    def check_finished(self):
        global stop_checking
        if not stop_checking:
            self.run_button.setText('Check Domains from List')
            self.run_button.setStyleSheet("background-color: #28a745; color: white;")
            QMessageBox.information(self, "Check Completed", "Domain check completed.")
        self.export_button.setEnabled(True)

    def show_rate_limit_message(self):
        QMessageBox.warning(self, "Rate Limit Reached", "The rate limit has been reached. No more domains can be checked at the moment.")
        self.run_button.setText('Check Domains from List')
        self.run_button.setStyleSheet("background-color: #28a745; color: white;")

    def sanitize_domain(self, domain):
        # Remove protocols (http, https) and www prefixes
        domain = re.sub(r'^https?://(www\.)?', '', domain)
        # Validate the domain using a regex pattern
        if re.match(r'^[a-zA-Z0-9-]{1,63}\.[a-zA-Z]{2,}$', domain):
            return domain
        return None

    def check_single_domain(self):
        domain = self.domain_entry.text()
        domain = self.sanitize_domain(domain)
        if domain and domain not in checked_domains:
            logger.debug("Checking single domain: {}".format(domain))
            result = self.check_domain(domain)
            logger.debug("Result for {}: {}".format(domain, result))
            domain_link = f"<a href='http://{domain}' style='color: #0078d7; text-decoration: none;'>{domain}</a>"
            if result == "UNAVAILABLE":
                current_text = self.unavailable_text.toHtml().strip()
                new_text = current_text + f"<div style='margin-bottom: 2px; margin-top: 0;'>{domain_link}</div>"
                self.unavailable_text.setHtml(new_text)
            else:
                current_text = self.available_text.toHtml().strip()
                new_text = current_text + f"<div style='margin-bottom: 2px; margin-top: 0;'>{domain_link}</div>"
                self.available_text.setHtml(new_text)
            results.append((domain, result))
            checked_domains.add(domain)
            self.export_button.setEnabled(True)
        elif domain in checked_domains:
            logger.warning("Duplicate domain check attempted: {}".format(domain))
            QMessageBox.warning(self, "Duplicate Domain", "This domain has already been checked.")
        else:
            logger.warning("Invalid domain input")
            QMessageBox.warning(self, "Error", "Please enter a valid domain name.")

    def check_domain(self, domain):
        try:
            details = whois.whois(domain)
            details_formatted = pprint.pformat(details)
            logger.debug("Raw WHOIS details for {}: \n{}".format(domain, details_formatted))
            
            # Determine if the domain is unavailable based on multiple factors
            if details.domain_name and details.status:
                logger.debug("Domain {} is UNAVAILABLE, details: \n{}".format(domain, details_formatted))
                return "UNAVAILABLE"
            elif details.name_servers:
                logger.debug("Domain {} is UNAVAILABLE, details: \n{}".format(domain, details_formatted))
                return "UNAVAILABLE"
            else:
                logger.debug("Domain {} is AVAILABLE, details: \n{}".format(domain, details_formatted))
                return "AVAILABLE"
        except Exception as e:
            logger.error("Error checking domain {}: {}".format(domain, e))
            if "rate limit" in str(e).lower():
                return "RATE_LIMIT"
            return "AVAILABLE"

    def export_results(self):
        if results:
            sorted_results = sorted(results, key=lambda x: x[1])  # Sort: available ("AVAILABLE") first, then unavailable ("UNAVAILABLE")
            df = pd.DataFrame(sorted_results, columns=["Domain", "Availability"])
            options = QFileDialog.Options()
            current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"domain_results_{current_time}.csv"
            file_path, _ = QFileDialog.getSaveFileName(self, "Export Results", default_name, "CSV Files (*.csv);;Excel Files (*.xlsx);;JSON Files (*.json);;Text Files (*.txt)", options=options)
            if file_path:
                if file_path.endswith(".csv"):
                    df.to_csv(file_path, index=False)
                elif file_path.endswith(".xlsx"):
                    df.to_excel(file_path, index=False)
                elif file_path.endswith(".json"):
                    df.to_json(file_path, orient='records', lines=True)
                elif file_path.endswith(".txt"):
                    df.to_csv(file_path, index=False, sep='\t')
                else:
                    QMessageBox.warning(self, "Error", "Invalid file format")
                    return
                QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")
        else:
            QMessageBox.warning(self, "Error", "No results to export")

def main():
    app = QApplication(sys.argv)
    checker = DomainMonkey()
    checker.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()