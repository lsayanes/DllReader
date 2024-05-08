# DllReader
Display the exported functions in a Windows dll

Need to get and display the export table of the exported functions in a Windows DLL from the code, and use "low level" (not so low...) techniques to access the export table information in the PE (Portable Executable) structure of the DLL. 
This involves opening the DLL file, reading its PE structure and extracting the necessary information. 

This simple console program allows to list the exported functions.
