Steam Input Lease
=================

Stops Steam Input from holding your controllers while a game runs, so the game
can use them directly. Steam gets them back when the game exits.


Install
-------

1. Exit Steam completely (Steam > Exit, not just closing the window).

2. Copy XInput1_4.dll and steam-input-lease.exe into your Steam folder, next
   to steam.exe. That is usually:

     C:\Program Files (x86)\Steam

   If that folder already has an XInput1_4.dll (ValvePlug and Special K use
   the same name), keep it and rename ours to dinput8.dll instead.

3. Start Steam.

To check that Steam loaded it, open a terminal in the Steam folder and run:

     .\steam-input-lease.exe --status

"Gate active" means it is working.


Steam games
-----------

Open the game's Properties, and under General > Launch Options enter:

     "C:\Program Files (x86)\Steam\steam-input-lease.exe" -- %command%

Use your own Steam path. Options you already had go after %command%.


Non-Steam games added to Steam
------------------------------

Put the same line into the shortcut's Launch Options and leave Target pointing
at the game.


Outside Steam
-------------

Steam must be running. Make a Windows shortcut with this target:

     "C:\Program Files (x86)\Steam\steam-input-lease.exe" -- "D:\Games\Example\game.exe"

Add the game's own arguments after its path.


Good to know
------------

- A console window stays open behind the game while it runs. That is the
  launcher waiting for the game to exit.
- If the controllers cannot be taken from Steam, for example because Steam was
  not restarted after installing, the game still starts normally.
  steam-input-lease.log next to the launcher says why.


Uninstall
---------

Exit Steam, delete XInput1_4.dll (or dinput8.dll), steam-input-lease.exe and
the steam-input-*.log files from the Steam folder, and remove the launch
options.
