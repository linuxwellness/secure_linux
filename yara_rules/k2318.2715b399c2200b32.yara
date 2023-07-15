
rule k2318_2715b399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2715b399c2200b32"
     cluster="k2318.2715b399c2200b32"
     cluster_size="3347"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['90e052faae59ad6253cd6374bf546a8e49d1740b','4ff9068435896994757d3e5fb10ad10f4dfb0236','50007c48dff71c4d735c7381e52143af1317d2f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2715b399c2200b32"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
