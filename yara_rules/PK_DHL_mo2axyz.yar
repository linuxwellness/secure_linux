rule PK_DHL_mo2axyz : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-15"
        comment = "Phishing Kit - DHL - 'Copyright all Reserved to Mo2aXYZ'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "auth"
        $spec_dir2 = "source"
        $spec_file1 = "config.php"
        $spec_file2 = "send.php"
        $spec_file3 = "waves.jpg"
        $spec_file4 = "dhl-logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
