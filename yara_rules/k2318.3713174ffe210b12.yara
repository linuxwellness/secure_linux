
rule k2318_3713174ffe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713174ffe210b12"
     cluster="k2318.3713174ffe210b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html redirector iframe"
     md5_hashes="['85882ecf27bdd3375023005db2063867f0e158b2','cf42f2d624e78d65b33cba3653313f4ff58af648','2d6e668dbed1c63d366153542bf8c3b2c0437627']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713174ffe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
