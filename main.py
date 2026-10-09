import sys
import os

# Add parent directory to path to allow running directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_email_analyzer.gui.app import EmailAnalyzerGUI

def main():
    app = EmailAnalyzerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
