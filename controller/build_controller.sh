# controller/build_controller.sh
pyinstaller --onefile --windowed --add-data "icons/*.png:icons" controller_ui.py