
rule m2321_51147294d6830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.51147294d6830912"
     cluster="m2321.51147294d6830912"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['00c9ddba9fe1e70aae3bfdf8ca7bb134','02a1d5c04f87f9e8a6cd50eefd9ac113','faf0727d79259e7a13c963d9664ce12d']"

   strings:
      $hex_string = { 3d4bbe9804a92c1d49a68f608219662861c6997d8048f16ec027170de39f5e535c41f01c2bc377fb5ddf9d813b8b13c1ed5a6f577d76cd2539f53e7c6cbb6ac9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
