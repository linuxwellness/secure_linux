
rule m2318_23bd204dd9a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.23bd204dd9a30b12"
     cluster="m2318.23bd204dd9a30b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2d93578bfd7a9146117036f88e9256f2','5c2417c1a4ad01f74cc9acde4f14e0fc','a596b076e4985b7b3b120c36fee00fb5']"

   strings:
      $hex_string = { 6a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
