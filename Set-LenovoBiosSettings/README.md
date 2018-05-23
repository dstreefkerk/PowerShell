# Set-LenovoBiosSettings
A PowerShell script built to ease the deployment of Lenovo BIOS settings as part of a ConfigMgr task sequence. Can also be run standalone.

Some benefits of using this script:
* Store BIOS settings for each model PC in a folder, and the script will automatically select the correct one
* Pass in a BIOS password as a parameter to the script
* Use multiple folders if you wish to apply certain settings at the beginning of a task sequence, and certain other settings at the end

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
Set-LenovoBiosSettings -SettingsFolder PreOSD -BiosPassword correcthorsestaple
```
## Helper Script
I've written a helper script that lists all of the current BIOS settings, as well as the possible values for each setting. It can be found here:
https://gist.github.com/dstreefkerk/05d88003eeb2b7f2d66b51c6f62ac23a
