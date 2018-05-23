# Set-LenovoBiosSettings
A PowerShell script built to ease the deployment of Lenovo BIOS settings as part of a ConfigMgr task sequence. Can also be run standalone.

Some benefits of using this script:
* Store BIOS settings for each model PC in a folder, and the script will automatically select the correct one
* Pass in a BIOS password as a parameter to the script
* Store different sets of settings in folders. Apply a set by specifying the folder name via the -SettingsFolder parameter
* Settings are stored in simple .TXT files in name,value format. # comments are supported, so you can document your BIOS setting choices

## Examples

#### Apply BIOS settings for a PC from the Settings folder, without specifying a BIOS password
*Note that a settings file matching this format must exist in the Settings folder - MANUFACTURER_MODEL.txt*
```powershell
Set-LenovoBiosSettings
```

#### Apply BIOS settings for a PC from the "PreOSD" folder, without specifying a BIOS password
*Note that a settings file matching this format must exist in the PreOSD folder - MANUFACTURER_MODEL.txt*
```powershell
Set-LenovoBiosSettings -SettingsFolder PreOSD
```

#### Apply BIOS settings for a PC from the "PostOSD" folder, specifying a BIOS password of 'correcthorsestaple'
*Note that a settings file matching this format must exist in the PostOSD folder - MANUFACTURER_MODEL.txt*
```powershell
Set-LenovoBiosSettings -SettingsFolder PostOSD -BiosPassword correcthorsestaple
```
## Logging
Output from the script is logged to a file 'LenovoBiosSettings.log' in the SMSTSLog folder. After OSD, this file is located in C:\Windows\CCM\Logs

## Helper Script
I've written a helper script that lists all of the current BIOS settings, as well as the possible values for each setting. It can be found here:
https://gist.github.com/dstreefkerk/05d88003eeb2b7f2d66b51c6f62ac23a
