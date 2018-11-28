gnome-keyring-sharp
-------------------

gnome-keyring-sharp is a fully managed implementation of libgnome-keyring.

The original frozen repository of gnome-keyring-sharp can be found at:

https://github.com/mono/gnome-keyring-sharp

libgnome and gnome-keyring-sharp are considered *deprecated*.
You're advised, if possible, to use more modern methods.
Nevertheless, Ubuntu and other linux distributions still use libgnome as of 2018.

What is it
----------
When the gnome-keyring-daemon is running, you can use this library to retrieve/store
confidential information such as passwords, notes or network services user information
from your csharp application.

Directory Layout
----------------
	docs/
		Monodoc documentation for the library

	sample/
		Sample programs using the library

	src/
		Source files for the library
