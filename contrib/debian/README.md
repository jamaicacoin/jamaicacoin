
Debian
====================
This directory contains files used to package jamaicacoind/jamaicacoin-qt
for Debian-based Linux systems. If you compile jamaicacoind/jamaicacoin-qt yourself, there are some useful files here.

## jamaicacoin: URI support ##


jamaicacoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install jamaicacoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your jamaicacoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/jamaicacoin128.png` to `/usr/share/pixmaps`

jamaicacoin-qt.protocol (KDE)

