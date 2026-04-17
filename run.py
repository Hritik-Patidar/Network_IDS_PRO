import webbrowser
import os
import sys
from threading import Timer
from app import create_app

app = create_app()


def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/")


if __name__ == '__main__':
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        Timer(2, open_browser).start()

    app.run(host='127.0.0.1', port=5000, debug=False)