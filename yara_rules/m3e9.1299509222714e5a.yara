
rule m3e9_1299509222714e5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1299509222714e5a"
     cluster="m3e9.1299509222714e5a"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="autorun mepaow lamer"
     md5_hashes="['1094e2fdd3d03b2f837fdb6f91a70c47','39c1fddf26cfa9bb85f94c4bd0e36716','8429679c12172bab84f220975d2ad321']"

   strings:
      $hex_string = { bbe8e441a37d7749c99016d139e33d2bb76e033ba45c50730555b84ad9be8783e54bfb6995236d98027e256f275d99deb1f8a097aeb294eb3cda6a099154d09d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
