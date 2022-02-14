This is my own powershell script to clean up windows 10 and make it run better. It does nto give you any options, it is just my preferences.

## How to Run
Paste this command into Powershell (admin):
``` powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/MaxAFriedrich/win10script/master/win10debloat.ps1'))
```
Or, shorter:
```
iwr -useb https://raw.githubusercontent.com/MaxAFriedrich/win10script/master/win10debloat.ps1 | iex
```
