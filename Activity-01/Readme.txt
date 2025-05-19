Bima Kristiawan 2079477
IT 390R Activity: Recursive Directory Scanner with Python

I chose enhancement 2, group files by folder summary

To run the script, I use "python scan.py test_root" command 

This is the output:
PS C:\Users\bimak\OneDrive\Documents\College\9. Spring 2025\IT 390R\activities-bimakrist\Activity-01> python .\scan.py .\test_root\

Scanning: C:\Users\bimak\OneDrive\Documents\College\9. Spring 2025\IT 390R\activities-bimakrist\Activity-01\test_root
Found 20 text files:

File                                      Size (KB)
----------------------------------------------------
docs\file0.txt                                  0.1
docs\file1.txt                                  0.1
docs\file2.txt                                  0.1
docs\file3.txt                                  0.1
docs\file4.txt                                  0.1
logs\file0.txt                                  0.1
logs\file1.txt                                  0.1
logs\file2.txt                                  0.1
logs\file3.txt                                  0.1
logs\file4.txt                                  0.1
logs\archive\file0.txt                          0.1
logs\archive\file1.txt                          0.1
logs\archive\file2.txt                          0.1
logs\archive\file3.txt                          0.1
logs\archive\file4.txt                          0.1
docs\subfolder\file0.txt                        0.1
docs\subfolder\file1.txt                        0.1
docs\subfolder\file2.txt                        0.1
docs\subfolder\file3.txt                        0.1
docs\subfolder\file4.txt                        0.1
----------------------------------------------------
Total size: 2.0 KB

Summary:
  docs/           —    5 files,   0.5 KB
  docs\subfolder/ —    5 files,   0.5 KB
  logs/           —    5 files,   0.5 KB
  logs\archive/   —    5 files,   0.5 KB