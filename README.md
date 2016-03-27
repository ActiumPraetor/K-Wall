# K-Wall
### Open-Source Anti-RMT-Spam Firewall

Welcome!

If you'd like to obtain ready-to-run precompiled binaries of K-Wall, please click the "binaries" folder above. That's where they live.

&nbsp;

### What Is K-Wall?

K-Wall is a specific type of firewall built for a specific purpose, which in a nutshell is this: adding comprehensive spam detection and filtration capabilities based on regular expressions to games that have integrated text-based "chat" functionality. K-Wall adds powerful filtration tools to any game that passes chat traffic "in the clear" (read: uncompressed/unencrypted). (Trivia: The "K" in K-Wall stands for Kleene, in honor of Stephen Cole Kleene, the inventor of regular expressions.)

Tell K-Wall what IP address(es) and port(s) to listen to (up to eight total), and any incoming packet traffic on that IP/port (or set of them) is procesed and scanned. Traffic that trips enough filters is logged and dropped, and everything else is passed on unmodified to the game client. The game never sees K-Wall, and never receives any spam chat that K-Wall drops.

&nbsp;

### System Requirements

K-Wall supports Windows Vista and later, both 32- and 64-bit. Please note that K-Wall uses a network filter driver that requires elevated privileges, and thus MUST be run as an administrator.

&nbsp;

### K-Wall Features

» K-Wall does not violate the ToS/AUP of any game, as it is NOT a "third-party tool" or a cheat program; it's literally a customized, purpose-specific network firewall. K-Wall does not hook to any game process, but instead hooks to Windows' integrated packet filtering service.

» K-Wall is ignored by "anti-cheat" software often used with F2P MMOs (e.g., GameGuardian), again since it is a network firewall and doesn't intrude upon the game itself in any way.

» Full Unicode 8.0 support, including built-in decode capability for UTF-8, UTF-16LE, UTF-16BE, and UTF32 text, thanks to the International Components for Unicode libraries.

» Game-agnostic design. K-Wall can process any chat text it can "see," regardless of the game. (Hint: This may have other uses outside game chats...)

» Per-game configuration, for maximum flexibility and customization.

» Multi-step deobfuscation converts or removes characters spammers like to use in order to bypass filters. Convert lookalike characters (e.g., "ø" becomes "o") and even multiple-character sequences (e.g., "|\/|" becomes "m"), strip out punctuation and whitespace (to catch gapped-out characters), casefold, normalize Unicode confusables (based on the Unicode Consortium's suggested method), and more.

» Comprehensive, fully-Unicode-aware RegExp engine via ICU'd RegEx libraries, which can detect any valid character across the entire Unicode codepage space, including other planes outside the BMP.

» Multi-threaded application, coded in C++ for excellent performance without requiring .NET.

» Full source code is available for both K-Wall and for all of its prerequisite libraries.
