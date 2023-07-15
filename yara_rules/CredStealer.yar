rule CredStealESY : For CredStealer

{

 meta:

description = "Generic Rule to detect the CredStealer Malware"

author = "IsecG – McAfee Labs"

date = "2015/05/08"

reference = "https://securingtomorrow.mcafee.com/mcafee-labs/when-hackers-get-hacked-the-malware-servers-of-a-data-stealing-campaign/"

strings:

$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout

$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module

 condition:

$my_hex_string and $my_hex_string2

}
