
rule m3f7_63310084fa630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63310084fa630912"
     cluster="m3f7.63310084fa630912"
     cluster_size="976"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0024ee98ae1e832b2c2f671d32fcc4f8','00785c36c7d2db2b6a5282fb83351f9d','03d4744b009a776901443821dc85600a']"

   strings:
      $hex_string = { 2043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e6420 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
