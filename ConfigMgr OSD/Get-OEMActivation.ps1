# Retrieve the OEM product key from the machine using WMI, change the key in Windows, and then Activate Windows
#
# Adapted from here: https://blogs.technet.microsoft.com/in-teaching-others-we-teach-ourselves/2016/12/13/how-to-deploy-windows-10-with-a-oem-product-key-from-the-bios-with-microsoft-deployment-toolkit/

# Retrieve the OEM key using WMI
$oemKey = (Get-WmiObject SoftwareLicensingService).OA3xOriginalProductKey

if ($oemKey) {

    # Switch to using the OEM key
    Invoke-Expression -Command "cscript.exe /b C:\Windows\System32\slmgr.vbs -ipk $oemKey" | Out-Null

    # Activate Windows
    Invoke-Expression -Command "cscript.exe /b C:\Windows\System32\slmgr.vbs -ato" | Out-Null

}
