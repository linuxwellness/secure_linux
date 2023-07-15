/*
      _____        __  __  ___        __      
     / ___/__  ___/ / /  |/  /__  ___/ /__    
    / (_ / _ \/ _  / / /|_/ / _ \/ _  / -_)   
    \___/\___/\_,_/_/_/__/_/\___/\_,_/\__/    
     \ \/ / _ | / _ \/ _ |   / _ \__ __/ /__  
      \  / __ |/ , _/ __ |  / , _/ // / / -_) 
      /_/_/ |_/_/|_/_/ |_| /_/|_|\_,_/_/\__/  
      Florian Roth - v0.5.0 October 2019
      
      A proof-of-concept rule that shows how easy it actually is to detect red teamer
      and threat group tools and code 
*/

rule IDDQD_Godmode_Rule {
   meta:
      description = "This is the most powerful YARA rule. It detects literally everything."
      author = "Florian Roth"
      reference = "Internal Research - get a Godmode YARA rule set with Valhalla by Nextron Systems"
      date = "2019-05-15"
      score = 60
   strings:
      /* Plain strings */
      $s01 = "sekurlsa::logonpasswords" ascii wide nocase           /* Mimikatz Command */
      $s02 = "ERROR kuhl" wide                                      /* Mimikatz Error */
      $s03 = /(@subtee|@mattifestation|@enigma0x3)/ fullword ascii  /* Red Team Tools */
      $s04 = " -w hidden " ascii wide                               /* Power Shell Params */
      $s05 = " -decode " ascii wide                                 /* certutil command */
      $s06 = "Koadic." ascii                                        /* Koadic Framework */
      $s07 = "ReflectiveLoader" fullword ascii wide                 /* Generic - Common Export Name */
      $s08 = "InjectDLL" fullword ascii wide                        /* DLL Injection Keyword */
      $s09 = "[System.Convert]::FromBase64String(" ascii wide       /* PowerShell - Base64 Encoded Payload */
      $s10 = /\\(Release|Debug)\\ms1[2-9]/ ascii                    /* Exploit Codes / PoCs */
      $s11 = "/meterpreter/" ascii                                  /* Metasploit Framework - Meterpreter */
      $s12 = / (-e |-enc |'|")(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA)/ ascii wide  /* PowerShell Encoded Code */
      $s13 = /  (sEt|SEt|SeT|sET|seT)  / ascii wide                 /* Casing Obfuscation */
      $s14 = ");iex " nocase ascii wide                             /* PowerShell - compact code */ 
      $s15 = / (cMd\.|cmD\.|CmD\.|cMD\.)/ ascii wide                /* Casing Obfuscation */
      $s16 = /(TW96aWxsYS|1vemlsbGEv|Nb3ppbGxhL|TQBvAHoAaQBsAGwAYQAv|0AbwB6AGkAbABsAGEAL|BNAG8AegBpAGwAbABhAC)/ ascii wide /* Base64 Encoded UA */
      $s17 = "Nir Sofer" fullword wide                              /* Hack Tool Producer */
      $s18 = "Web Shell By " nocase ascii                           /* Web Shell Copyright */
      $s19 = "impacket." ascii                                      /* Impacket Library */
      $s20 = /\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject|dump)/ nocase  /* Hack Tool Output Pattern */
      $s21 = "ecalper" fullword ascii wide                          /* Reversed String - often found in scripts or web shells */
      $s22 = "0000FEEDACDC}" ascii wide                             /* Squiblydoo - Class ID */
      $s23 = /(click enable editing|click enable content|"Enable Editing"|"Enable Content")/ ascii  /* Phishing Docs */
      $s24 = "vssadmin delete shadows"                              /* Shadow Copy Deletion - often used in Ransomware */
      $s25 = "stratum+tcp://"                                       /* Stratum Address - used in Crypto Miners */
      $s26 = /\\(Debug|Release)\\(Downloader|Key[lL]og|[Ii]nject|Steal|By[Pp]ass|UAC|Dropper|Loader|CVE\-)/  /* Typical PDB Strings 1 */
      $s27 = /(Dropper|Downloader|Bypass|Injection)\.pdb/ nocase    /* Typical PDF strings 2 */
      /* Combos */
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xf1 = "Mozilla/5.0" ascii wide
   condition:
      1 of ($s*) or 
      ( $xo1 and not $xf1 )
}