
rule k2318_3998d6b9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3998d6b9ca800932"
     cluster="k2318.3998d6b9ca800932"
     cluster_size="237"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['a8c96f4eb4c88ce3cd63923b484cde7d647cbde3','d5e3c8bb6a8bcf287286254c63af43f797035d93','d105dc28aeb23975f3acde3c64f686b1306da1fe']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3998d6b9ca800932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
