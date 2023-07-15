
rule k2321_4b10d846d7a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.4b10d846d7a31932"
     cluster="k2321.4b10d846d7a31932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['060453c5f5e3dd6140183d0c250a36ac','7da25131cf80919dd4a12be7ecc28e56','f230d28e0e22761c51d7eaafe46d56ba']"

   strings:
      $hex_string = { 27ddc56563ac231c2b0ff35046fa10ca3f585c7b20b987b54ee3d68913b1a315c334d94bc67ca2eaed3ae85ebc560d248d6fb6f209b4f46d49f13b724fd59cee }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
