rule PK_USPS_okbbx : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-12"
        comment = "Phishing Kit - USPS - '$_POST[okbbx]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "inc"
        // specific file found in PhishingKit
        $spec_file = "index9.php"
        $spec_file2 = "thanks.php"
        $spec_file3 = "functions.php"
        $spec_file4 = "app.php"
        $spec_file5 = "id.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
