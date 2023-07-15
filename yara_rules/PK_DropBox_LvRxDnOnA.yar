rule PK_DropBox_LvRxDnOnA : Dropbox
{
    meta:
        description = "Phishing Kit impersonating DropBox"
        licence = ""
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-10"
        comment = "Phishing Kit - DropBox - 'Skype:Lvrxdnona ICQ:666133716'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file = "process.php"
        $spec_file2 = "index.html"
        $spec_file3 = "ajax-loading-small@2x-vflAxdZTP.gif"
	    $spec_file4 = "to.php"

    condition:
        // look for the ZIP header and all
        uint32(0) == 0x04034b50 and $local_file and $spec_file and $spec_file2 and $spec_file3 and $spec_file4
}
