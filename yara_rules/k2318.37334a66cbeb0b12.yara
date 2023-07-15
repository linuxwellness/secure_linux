
rule k2318_37334a66cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37334a66cbeb0b12"
     cluster="k2318.37334a66cbeb0b12"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['9339f1f68d8e7eb319d05617771df34e0845e83b','c9932a50ad3f6428c15c16cd80b438bc9159c18d','1f8a18df9511cbcfe4c0b3122a761121b1883952']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37334a66cbeb0b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
