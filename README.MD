Requiremts
1. Arduino Leonardo ATmega32u4

Steps For Getting Ardino HEX File

1. Flash Arduino .ino File Using Arduino IDE.
2. In Arduino IDE App data folder there will be different hexfile
3. We need hex file without the bootloader

Steps For Compiling

1. Minify Python code :- https://pyobfuscate.com/minifier
2. Download upx :- https://github.com/upx/upx/releases/
3. nuitka compile commend :- nuitka --onefile --mingw64 --enable-plugin=tk-inter --windows-icon-from-ico=BLACK.ico --include-data-file=Silence.hex=./Silence.hex --include-data-file=./avrdude.exe=avrdude.exe --include-data-file=./avrdude.conf=avrdude.conf --include-data-file=./BLACK.ico=BLACK.ico --windows-console-mode=disable --assume-yes-for-downloads --plugin-enable=upx --upx-binary="C:\Users\jaypa\Downloads\upx-5.0.0-win64" --windows-uac-admin --product-name="Silence Ai" --product-version="1.0.0" --file-description="Silence Ai By RolexDev" --follow-imports  mini_main.py

4. Passthrough VM Protect

