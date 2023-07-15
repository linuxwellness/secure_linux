
rule k3e9_51a933260aab6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a933260aab6b32"
     cluster="k3e9.51a933260aab6b32"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['18b1feb3ecd0e43086af1e17da1ee87c','1f8863e993f55ae5ef8f8facdc507f67','c68c012afaf408f78128623ccff1adb8']"

   strings:
      $hex_string = { 0580f97e722e33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
