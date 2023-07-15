
rule ofc8_431561d4dec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.431561d4dec30932"
     cluster="ofc8.431561d4dec30932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['3e9e14b756d313388eb2173bd925da6c9b03ba96','71c320550baedfa2cb92065d835bc44db08a798a','32a3a4df5ba7153122ef32c8bb39db9e8b945b3b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.431561d4dec30932"

   strings:
      $hex_string = { 3ac1058810847900c46e260f149329113044832f15687ec7b87ce365deafac0d7d5eadbac3ebd570a83e2a736de8fe013125f0ff6b80dd540b34049cb3c6431a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
