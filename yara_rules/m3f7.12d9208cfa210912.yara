
rule m3f7_12d9208cfa210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.12d9208cfa210912"
     cluster="m3f7.12d9208cfa210912"
     cluster_size="84"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['04562289a2aa5057cc152ae0140c493b','08e291f87f3c4365915bf1f0a07195b2','38f99deb6d4bc624958c2900ad2cf97e']"

   strings:
      $hex_string = { 626a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
