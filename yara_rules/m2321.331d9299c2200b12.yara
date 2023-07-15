
rule m2321_331d9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.331d9299c2200b12"
     cluster="m2321.331d9299c2200b12"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['07b01af32feb973b01244b33d6e3f135','08d821606f7f83bf4a037fd9495f1aba','d5cb64c0b7c28f6d3986bd330e9f43a6']"

   strings:
      $hex_string = { 1125c933a68a61f0c0262a5573b3c768cbeffa6e182c3934ff787936403feb3dbc843c92c3ddb5a7b8a0d744d0ce061d2959905b2e7ac6fccc382989ae4c6fed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
