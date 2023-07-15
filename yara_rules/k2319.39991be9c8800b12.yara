
rule k2319_39991be9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39991be9c8800b12"
     cluster="k2319.39991be9c8800b12"
     cluster_size="444"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['34622ee5296bda3c734cc67f13e0d22e45422936','23889aa92c6931e9907f3c0eadd9a3275e379611','ec9d19d274a1327f2f7b2cb240d3f49c7651f36c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39991be9c8800b12"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
