
rule k2318_27143299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27143299c2200b32"
     cluster="k2318.27143299c2200b32"
     cluster_size="111"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['8a0b9580033e046414d8a4582a0a4d4d740be53f','d75872ee8e9efbd8f01512ed58de45fb406ac978','ff3b036771a61694fb32b6dbea24523f1b82e44f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27143299c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
