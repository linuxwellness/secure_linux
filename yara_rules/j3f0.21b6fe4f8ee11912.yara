
rule j3f0_21b6fe4f8ee11912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.21b6fe4f8ee11912"
     cluster="j3f0.21b6fe4f8ee11912"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious genericrxci"
     md5_hashes="['00aedbb13f54b2445b10a2633639bd68','01dd9843ae86540a05a6cc74bcc2898c','69353520fba61125ed5388f7ef8f4126']"

   strings:
      $hex_string = { e48b4d8403483c8b45f00fb740108d4401188945e88b45912b8550ffffff506a008b4584038550ffffff50e8cf07000083c40c8d45f4506a040fb645886bc028 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
