rule MALW_trickbot_bankBot : Trojan
{
meta:
  author = "Marc Salinas @Bondey_m"
  description = "Detects Trickbot Banking Trojan"
  reference = "https://www.securityartwork.es/wp-content/uploads/2017/06/Informe_Evoluci%C3%B3n_Trickbot.pdf"
strings:
  $str_trick_01 = "moduleconfig"
  $str_trick_02 = "Start"
  $str_trick_03 = "Control"
  $str_trick_04 = "FreeBuffer"
  $str_trick_05 = "Release"
condition:
  all of ($str_trick_*)
}

rule MALW_systeminfo_trickbot_module : Trojan
{
meta:
  author = "Marc Salinas @Bondey_m"
  description = "Detects systeminfo module from Trickbot Trojan"
  reference = "https://www.securityartwork.es/wp-content/uploads/2017/06/Informe_Evoluci%C3%B3n_Trickbot.pdf"
strings:
  $str_systeminf_01 = "<program>"
  $str_systeminf_02 = "<service>"
  $str_systeminf_03 = "</systeminfo>"
  $str_systeminf_04 = "GetSystemInfo.pdb"
  $str_systeminf_05 = "</autostart>"
  $str_systeminf_06 = "</moduleconfig>"
condition:
all of ($str_ systeminf_*)
}

rule MALW_dllinject_trickbot_module : Trojan
{
meta:
  author = "Marc Salinas @Bondey_m"
  description = " Detects dllinject module from Trickbot Trojan"
  reference = "https://www.securityartwork.es/wp-content/uploads/2017/06/Informe_Evoluci%C3%B3n_Trickbot.pdf"
strings:
  $str_dllinj_01 = "user_pref("
  $str_dllinj_02 = "<ignore_mask>"
  $str_dllinj_03 = "<require_header>"
  $str_dllinj_04 = "</dinj>"
condition:
  all of ($str_ dllinj_*)
}

rule MALW_mailsercher_trickbot_module : Trojan
{
meta:
  author = "Marc Salinas @Bondey_m"
  description = " Detects mailsearcher module from Trickbot Trojan"
  reference = "https://www.securityartwork.es/wp-content/uploads/2017/06/Informe_Evoluci%C3%B3n_Trickbot.pdf"
strings:
  $str_mails_01 = "mailsearcher"
  $str_mails_02 = "handler"
  $str_mails_03 = "conf"
  $str_mails_04 = "ctl"
  $str_mails_05 = "SetConf"
  $str_mails_06 = "file"
  $str_mails_07 = "needinfo"
  $str_mails_08 = "mailconf"
condition:
  all of ($str_mails_*)
}
