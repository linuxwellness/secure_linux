
rule k2318_291294cbc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.291294cbc6220932"
     cluster="k2318.291294cbc6220932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['14aa42b6b38d0779359fc9737961616d2245c06f','6ffef4a8cd457fd8b00f11ddc2503e58174fee6f','b97415872559538eec79facfafc790ac7a4a46fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.291294cbc6220932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
