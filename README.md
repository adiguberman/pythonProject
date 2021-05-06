#Interview Question
##Implementation
###1. Firmware Analyzer

Suppose that one of the automotive vendors sent to you a firmware archive
and asked you to find different security issues. We know that some of the
vendors are using a special authentication tokens in the following format:

Starting with "<Tkn" then later 3 digits, 5 English capital letters followed by a
"Tkn>". For example: <Tkn435JFIRKTkn>
You should implement a function that receives a path to a zip file on the disk
(the firmware file) and a path to a CSV file output. The function should find the
above pattern in all the files under the extracted file system of the zip file
(recursively in all the folders underneath to) and report the results into the
output CSV in the following format:

Path - The relative path of the found file to the location of the extracted
zip file.

Token - The identified token string

Occurrences - The number of occurrences of the Token inside the file path

The results should be sorted by (Path, Occurrences, Token)
The function also needs to print to the screen the total findings of each
token in all of the files. for example if token <Tkn435JFIRKTkn> was found
only in f1< 5 times and in f2 <3 times it should print <Tkn435JFIRKTkn> : 8,


###Notes:
You can create a zip file with a file system underneath with files that
contain the relevant tokens
Implement the question in python 3
You can assume that each file can be read into the memory
###Bonus : 
In order to increase performance - add thread pool or process pool to process the file system.
