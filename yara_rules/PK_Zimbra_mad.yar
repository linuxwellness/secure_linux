rule PK_ZortFX_mad : ZortFX
{
    meta:
        description = "Phishing Kit impersonating ZortFX Market"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-24"
        comment = "Phishing Kit - ZortFX - '--Mad--'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "Web Client Sign In_files"
        $spec_file = "verified.php"
        $spec_file2 = "upgradesuccessful.html"
        $spec_file3 = "zi.png"
        $spec_file4 = "commonloginzhtmlskin.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
