
rule k2319_29993499c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29993499c2200b32"
     cluster="k2319.29993499c2200b32"
     cluster_size="107"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['74859b9dd9882371a15443805618a091874219a1','ce7e8d24e59d687580f33429a0d15de7f5ccbd54','6d96b0651b83a16bfa7f42ad16ee4431ed10e27d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29993499c2200b32"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
