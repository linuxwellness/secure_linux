
rule j2319_039b689cca210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.039b689cca210932"
     cluster="j2319.039b689cca210932"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script megasearch multiplug"
     md5_hashes="['5020ed9ed681b34503902e70c9530ad72baa9771','03835f1d013fb6db62503d5c4b3e27d19249377b','e752c17fd5b22587a6dc2527ccf5c7675b73e774']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.039b689cca210932"

   strings:
      $hex_string = { 2e67657454696d6528292f314533297d7d63617463682863297b72657475726e20307d7d7d2c6462636c6173733d7b656e67696e65733a5b227072666462222c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
